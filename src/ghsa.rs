use std::env;


use chrono::{Duration, Utc};
use reqwest::{
    blocking::Client,
    header::{ACCEPT, AUTHORIZATION, USER_AGENT},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// GitHub GraphQL APIのエンドポイント
static ENDPOINT: &str = "https://api.github.com/graphql";

#[derive(Debug, Serialize, Deserialize)]
pub struct GhsaResponse {
    pub data: Data,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Data {
    pub security_advisories: SecurityAdvisories,
}

/// GitHub Security Advisories
#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityAdvisories {
    /// A list of edges.
    pub edges: Vec<Edge>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Edge {
    /// The item at the end of the edge.
    pub node: Node,
}

/// The item at the end of the edge.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    /// The CVSS associated with this advisory
    pub cvss: Cvss,
    /// The GitHub Security Advisory ID
    pub ghsa_id: String,
    /// The severity of the advisory
    pub severity: String,
    /// A short plaintext summary of the advisory
    pub summary: String,
}

/// The CVSS associated with this advisory
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cvss {
    /// The CVSS vector string associated with this advisory
    pub vector_string: Option<String>,
}

/// GHSA GraphQL APIにリクエストを送信し、APIからのJSONレスポンスをデシリアライズした結果を返す。
pub fn fetch() -> anyhow::Result<GhsaResponse> {
    dotenvy::dotenv().ok();
    let gh_access_token = env::var("GH_ACCESS_TOKEN").expect("couldn't read GH_ACCESS_TOKEN");

    let yesterday = Utc::now().naive_utc().date() - Duration::days(1);
    let query = format!(
        r#"
query {{ 
  securityAdvisories(first: 10, publishedSince: "{}T00:00:00") {{
    edges {{
      node {{
       	ghsaId
        summary
        severity
        cvss {{
          vectorString
        }}
      }}
    }}
  }}
}}
"#,
        yesterday
    );

    let client = Client::new();
    let query = json!({ "query": query });
    let bearer = format!("bearer {gh_access_token}");
    let req = client
        .post(ENDPOINT)
        .header(USER_AGENT, "reqwest")
        .header(AUTHORIZATION, &bearer)
        .header(ACCEPT, "application/vnd.github.v4.idl")
        .json(&query);

    let resp = req.send()?.json::<GhsaResponse>()?;

    Ok(resp)
}

#[test]
fn test_fetch() {
    fetch().unwrap();
}
