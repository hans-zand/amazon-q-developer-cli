use aws_sdk_comprehend::{Client as ComprehendClient, types::LanguageCode};
use aws_sdk_cloudwatch::{Client as CloudWatchClient, types::{MetricDatum, Dimension}};
use aws_config::BehaviorVersion;

#[derive(Debug, Clone)]
pub struct PiiMatch {
    pub pii_type: String,
    pub matched_text: String,
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
}

pub struct PiiDetector {
    client: ComprehendClient,
    cloudwatch: CloudWatchClient,
}

impl PiiDetector {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let config = aws_config::defaults(BehaviorVersion::latest())
            .region("ap-southeast-2")
            .load()
            .await;
        let client = ComprehendClient::new(&config);
        let cloudwatch = CloudWatchClient::new(&config);
        
        Ok(Self { client, cloudwatch })
    }

    async fn send_pii_metric(&self, context: &str, pii_count: i32) -> Result<(), Box<dyn std::error::Error>> {
        let dimension = Dimension::builder()
            .name("Context")
            .value(context)
            .build();

        let metric = MetricDatum::builder()
            .metric_name("PIIDetected")
            .value(pii_count as f64)
            .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
            .dimensions(dimension)
            .build();

        self.cloudwatch
            .put_metric_data()
            .namespace("QCli/PII")
            .metric_data(metric)
            .send()
            .await?;

        Ok(())
    }

    pub async fn detect_pii(&self, text: &str) -> Result<Vec<PiiMatch>, Box<dyn std::error::Error>> {
        let response = self.client
            .detect_pii_entities()
            .text(text)
            .language_code(LanguageCode::En)
            .send()
            .await?;

        let mut matches = Vec::new();
        
        if let Some(entities) = response.entities {
            for entity in entities {
                if let (Some(pii_type), Some(begin_offset), Some(end_offset), Some(score)) = (
                    entity.r#type.as_ref(),
                    entity.begin_offset,
                    entity.end_offset,
                    entity.score,
                ) {
                    let start = begin_offset as usize;
                    let end = end_offset as usize;
                    let matched_text = text.get(start..end).unwrap_or("").to_string();
                    
                    matches.push(PiiMatch {
                        pii_type: format!("{:?}", pii_type),
                        matched_text,
                        start,
                        end,
                        confidence: score,
                    });
                }
            }
        }
        
        matches.sort_by_key(|m| m.start);
        Ok(matches)
    }

    pub async fn has_pii(&self, text: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let matches = self.detect_pii(text).await?;
        Ok(!matches.is_empty())
    }

    pub async fn redact_pii(&self, text: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut result = text.to_string();
        let matches = self.detect_pii(text).await?;
        
        // Process matches in reverse order to maintain correct indices
        for pii_match in matches.iter().rev() {
            let redacted = format!("[REDACTED_{}]", pii_match.pii_type);
            result.replace_range(pii_match.start..pii_match.end, &redacted);
        }
        
        Ok(result)
    }

    pub async fn check_and_warn(&self, text: &str, context: &str) -> Result<bool, Box<dyn std::error::Error>> {
        eprintln!("🔍 Checking {} for PII...", context);
        let matches = self.detect_pii(text).await?;
        
        if !matches.is_empty() {
            // Send CloudWatch metric
            let _ = self.send_pii_metric(context, matches.len() as i32).await;
            
            eprintln!("⚠️  PII detected in {}: {} entities found", context, matches.len());
            for pii_match in &matches {
                eprintln!("   - {}: {} (confidence: {:.2})", 
                    pii_match.pii_type, 
                    pii_match.matched_text,
                    pii_match.confidence
                );
            }
            eprintln!("   Consider removing sensitive information before proceeding.");
            eprintln!("📊 PII detection event sent to CloudWatch");
            return Ok(true);
        } else {
            eprintln!("✅ No PII detected in {}", context);
        }
        
        Ok(false)
    }
}
