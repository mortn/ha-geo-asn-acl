use std::fs;
use std::io::{self, BufRead, BufReader};
use sha2::{Sha256, Digest};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;
use tokio;
use httpdate;
use clap::Parser;

const FILE_URL: &str = "https://wetmore.ca/ip/haproxy_geo_ip.txt";
const SHA256_URL: &str = "https://wetmore.ca/ip/haproxy_geo_ip.sha256";
const LOCAL_FILE_PATH: &str = "haproxy_geo_ip.txt";
const LOCAL_FILE_CIDR: &str = "geoip.txt";

#[derive(Parser, Debug)]
#[command(name = "ha-geo-ip")]
#[command(about = "Filter IP geolocation data by country codes", long_about = None)]
struct Args {
    /// Country codes to filter (e.g., DK SE NO)
    #[arg(short = 'c', long = "country", required = true)]
    country_codes: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Convert all country codes to uppercase for case-insensitive matching
    let country_codes: Vec<String> = args.country_codes
        .iter()
        .map(|cc| cc.to_uppercase())
        .collect();
    
    let client = reqwest::Client::new();
    let mut headers = HeaderMap::new();

    // Check for local file and get its modification time for an If-Modified-Since header
    if let Ok(metadata) = fs::metadata(LOCAL_FILE_PATH) {
        if let Ok(modified_time) = metadata.modified() {
            let http_date = httpdate::fmt_http_date(modified_time);
            if let Ok(header_value) = HeaderValue::from_str(&http_date) {
                headers.insert("If-Modified-Since", header_value);
            }
        }
    }

    println!("Fetching IP geolocation data from: {}", FILE_URL);
    let response = client.get(FILE_URL).headers(headers).send().await?;

    let content = match response.status() {
        StatusCode::OK => {
            println!("New version of the file found, downloading...");
            let content = response.bytes().await?;
            
            // Verify SHA256 of the newly downloaded file
            println!("Verifying integrity with SHA256 from: {}", SHA256_URL);
            let sha256_response = client.get(SHA256_URL).send().await?;
            let sha256_content = sha256_response.text().await?;
            let expected_hash = sha256_content.trim().split_whitespace().next().unwrap_or("");

            let mut hasher = Sha256::new();
            hasher.update(&content);
            let calculated_hash = format!("{:x}", hasher.finalize());

            if calculated_hash != expected_hash {
                eprintln!("SHA256 mismatch! Downloaded file is corrupt.");
                eprintln!("Expected:   {}", expected_hash);
                eprintln!("Calculated: {}", calculated_hash);
                std::process::exit(1);
            }
            println!("SHA256 verification successful!");

            // Save the new content to the local file
            fs::write(LOCAL_FILE_PATH, &content)?;
            println!("Local file updated.");
            content.to_vec()
        },
        StatusCode::NOT_MODIFIED => {
            println!("Local file is already up-to-date. Processing local file.");
            fs::read(LOCAL_FILE_PATH)?
        },
        _ => {
            eprintln!("Failed to fetch file: {}", response.status());
            std::process::exit(1);
        }
    };

    // Process the content (either from download or local file)
    process_and_grep(&content, &country_codes)?;

    Ok(())
}

fn process_and_grep(content: &[u8], country_codes: &[String]) -> io::Result<()> {
    let reader = BufReader::new(content);
    
    println!("\nProcessing CIDR blocks for country codes: {:?}...", country_codes);
    
    let mut country_counts = std::collections::HashMap::new();
    let mut filtered_lines = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let columns: Vec<&str> = line.split_whitespace().collect();
        
        if columns.len() == 2 {
            let cidr_block = columns[0];
            let country_code = columns[1];
            
            if country_codes.iter().any(|cc| cc == country_code) {
                filtered_lines.push(format!("{} {}", cidr_block, country_code));
                *country_counts.entry(country_code.to_string()).or_insert(0) += 1;
            }
        }
    }
    
    // Write filtered results to LOCAL_FILE_CIDR
    let output_content = filtered_lines.join("\n");
    fs::write(LOCAL_FILE_CIDR, &output_content)?;
    
    println!("Filtered CIDR blocks written to: {}", LOCAL_FILE_CIDR);
    println!("\nSummary:");
    
    let mut total = 0;
    for code in country_codes {
        let count = country_counts.get(code).unwrap_or(&0);
        println!("{} CIDR blocks: {}", code, count);
        total += count;
    }
    
    println!("Total matching blocks: {}", total);

    Ok(())
}
