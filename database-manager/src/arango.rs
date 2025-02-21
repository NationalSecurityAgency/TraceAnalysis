//! A simple implementation for working with an arango database using their
//! http `REST` api.

use std::{io::Write, path::PathBuf, str::FromStr};

use anyhow::{anyhow, Result};
use reqwest::{Client, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, from_value, json, Value};
use tokio::sync::OnceCell;
use tracing::{debug, error, info, warn};
use url::Url;

/// Static instance of the ArangoManger that can be passed to the tokio
/// runtime when spawning tasks.
pub static INSTANCE: OnceCell<ArangoManager> = OnceCell::const_new();

/// Adds HTTP v1.1 + 'application/json' headers to `req`.
fn add_default_hdrs(req: RequestBuilder) -> RequestBuilder {
    req.version(reqwest::Version::HTTP_11)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json")
}

async fn check_response(response: Response, message: String) -> Result<()> {
    let status = response.status().is_success();
    let text = Value::from_str(&response.text().await?)?;
    debug!("{text}");
    match status {
        true => info!("{message} -> SUCCESS"),
        false => warn!("{message} -> FAILED"),
    };
    Ok(())
}

/// Contains details for connecting to an arango database instance.
pub struct ArangoManager {
    base_url: Url,
    db_name: String,
    http_client: Client,
    // session_id: Option<String>,
}

impl ArangoManager {
    pub async fn try_new(base_url: Url, db_name: String) -> Result<Self> {
        let manager = Self {
            base_url,
            db_name,
            http_client: Client::new(),
            // session_id: None,
        };

        debug!("Testing connection to {}", manager.base_url.as_str());
        let _ = manager.http_get("/")?.send().await?.error_for_status()?;

        Ok(manager)
    }

    // TODO: allow authentication
    // pub async fn try_new_with_auth(_base_url: Url, _user: &str, _pass: &str) -> Result<Self> {
    //     unimplemented!()
    // }

    // Below are some helper methods for building the http requests
    fn http_get(&self, api_path: &str) -> Result<RequestBuilder> {
        let req = self.http_client.get(self.base_url.join(api_path)?);
        Ok(add_default_hdrs(req))
    }

    fn http_post(&self, api_path: &str, body: &Value) -> Result<RequestBuilder> {
        let req = self.http_client.post(self.base_url.join(api_path)?);
        let req = req.body(body.to_string());
        Ok(add_default_hdrs(req))
    }

    fn http_put(&self, api_path: &str) -> Result<RequestBuilder> {
        let req = self.http_client.put(self.base_url.join(api_path)?);
        Ok(add_default_hdrs(req))
    }

    fn http_delete(&self, api_path: &str) -> Result<RequestBuilder> {
        let req = self.http_client.delete(self.base_url.join(api_path)?);
        Ok(add_default_hdrs(req))
    }

    // TODO: The following database methods should probably be their own
    // trait in case we want to add more database options.

    /* Databases */
    pub async fn create_db(&self) -> Result<()> {
        let message = format!("create_db({})", self.db_name);
        debug!("{message}");

        let api_path = "_api/database";
        let body = json!({"name": self.db_name});
        let response = self.http_post(api_path, &body)?.send().await?;

        check_response(response, message).await
    }

    pub async fn delete_db(&self) -> Result<()> {
        let message = format!("delete_db({})", self.db_name);
        debug!("{message}");

        let api_path = format!("_api/database/{}", self.db_name);
        let response = self.http_delete(&api_path)?.send().await?;

        check_response(response, message).await
    }

    /* Collections */
    pub async fn list_collections(&self) -> Result<Vec<String>> {
        let message = format!("list_collections()");
        debug!("{message}");

        let api_path = format!("_db/{}/_api/collection", self.db_name);
        let response = self.http_get(&api_path)?.send().await?;

        let mut v: Value = from_str(&response.error_for_status()?.text().await?)?;
        let collection_names_result: Result<Vec<String>> =
            from_value::<Vec<Value>>(v["result"].take())?
                .into_iter()
                .map(|mut v| from_value::<String>(v["name"].take()).map_err(anyhow::Error::from))
                .collect();

        collection_names_result
    }

    pub async fn create_collection(
        &self,
        name: &str,
        collection_type: CollectionType,
    ) -> Result<()> {
        let message = format!("create_collection({name}, {collection_type:?})");
        debug!("{message}");

        let api_path = format!("_db/{}/_api/collection", self.db_name);
        let body = json!({"name": name, "type": collection_type as u8});
        let response = self.http_post(&api_path, &body)?.send().await?;

        check_response(response, message).await
    }

    pub async fn delete_collection(&self, name: String) -> Result<()> {
        let message = format!("delete_collection({name})");
        debug!("{message}");

        let api_path = format!("_db/{}/_api/collection/{name}", self.db_name);
        let response = self.http_delete(&api_path)?.send().await?;

        check_response(response, message).await
    }

    pub async fn collection_info(&self, name: &str) -> Result<Option<CollectionInfo>> {
        let message = format!("collection_info{name}");
        debug!(message);

        let api_path = format!("_db/{}/_api/collection/{name}/count", self.db_name);
        let response = self.http_get(&api_path)?.send().await?;

        let status = response.status().is_success();
        let mut text = Value::from_str(&response.text().await?)?;
        let result = match status {
            false => {
                warn!("{message} => FAILED");
                None
            }
            true => Some(CollectionInfo {
                name: from_value::<String>(text["name"].take())?,
                doc_count: from_value::<u64>(text["count"].take())?,
                kind: from_value::<u8>(text["type"].take())?.try_into()?,
                indexes: self.collection_indexes_info(name).await?,
            }),
        };
        Ok(result)
    }

    async fn collection_indexes_info(&self, collection: &str) -> Result<Vec<IndexInfo>> {
        let message = format!("collection_indexes_info({collection})");
        debug!("{message}");

        let api_path = format!("_db/{}/_api/index", self.db_name);
        let response = self
            .http_get(&api_path)?
            .query(&[("collection", collection)])
            .send()
            .await?;

        let mut data = Value::from_str(&response.text().await?)?;
        let mut index_infos = Vec::new();
        for mut v in from_value::<Vec<Value>>(data["indexes"].take())? {
            index_infos.push(IndexInfo {
                name: from_value::<String>(v["name"].take())?,
                id: from_value::<String>(v["id"].take())?,
                kind: from_value::<String>(v["type"].take())?,
                fields: from_value::<Vec<String>>(v["fields"].take())?,
            });
        }
        Ok(index_infos)
    }

    pub async fn truncate_collection(&self, name: &str) -> Result<()> {
        let message = format!("truncate_collection({name})");
        debug!("{message}");

        let api_path = format!("_db/{}/_api/collection/{name}/truncate", self.db_name);
        let response = self.http_put(&api_path)?.send().await?;

        check_response(response, message).await
    }

    /* Indexes */
    pub async fn list_indexes_with_id(&self, collection: &str) -> Result<Vec<(String, String)>> {
        let message = format!("list_indexes_with_id({collection})");
        debug!("{message}");

        let api_path = format!("_db/{}/_api/index", self.db_name);
        let response = self
            .http_get(&api_path)?
            .query(&[("collection", collection)])
            .send()
            .await?;

        let mut v: Value = from_str(response.error_for_status()?.text().await?.as_str())?;
        let mut index_values = from_value::<Vec<Value>>(v["indexes"].take())?;
        let indexes_names = index_values
            .iter_mut()
            .map(|v| from_value::<String>(v["name"].take()).map_err(anyhow::Error::from))
            .collect::<Result<Vec<String>>>()?;
        let index_ids = index_values
            .iter_mut()
            .map(|v| from_value::<String>(v["id"].take()).map_err(anyhow::Error::from))
            .collect::<Result<Vec<String>>>()?;

        Ok(std::iter::zip(indexes_names.into_iter(), index_ids.into_iter()).collect())
    }

    pub async fn create_index(&self, collection: &str, index_details: Value) -> Result<()> {
        let message = format!("create_index({collection}, {})", index_details.to_string());
        debug!("{message}");

        let api_path = format!("_db/{}/_api/index", self.db_name);
        let response = self
            .http_post(&api_path, &index_details)?
            .query(&[("collection", collection)])
            .send()
            .await?;

        check_response(response, message).await
    }

    pub async fn delete_index(&self, index_id: String) -> Result<()> {
        let message = format!("delete_index({index_id})");
        debug!("{message}");

        let api_path = format!("_db/{}/_api/index/{index_id}", self.db_name);
        let response = self.http_delete(&api_path)?.send().await?;
        check_response(response, message).await
    }

    /* Import Data */

    pub async fn arangoimport(&self, collection: &str, source: PathBuf, quiet: bool) -> Result<()> {
        let message = format!("arangoimport({collection}, {source:?})");
        debug!("{message}");

        let num_cpus = std::thread::available_parallelism()?.to_string();
        let endpoint = ArangoEndpoint::from(&self.base_url);
        let args = vec![
            "--server.endpoint",
            &endpoint.endpoint,
            "--server.database",
            self.db_name.as_str(),
            "--server.authentication",
            "false", // FIXME
            "--threads",
            &num_cpus,
            "--collection",
            collection,
            "--file",
            source.to_str().expect("File path was not unicode."),
            "--type",
            source
                .extension()
                .ok_or_else(|| anyhow!("Source file: '{source:?}' doesn't have a file extension!"))?
                .to_str()
                .expect("File extension was invalid unicode."),
        ];

        let output = tokio::process::Command::new("arangoimport")
            .args(&args)
            .output()
            .await?;

        debug!("arangoimport {}", args[..].join(" "));
        if !quiet {
            println!("Stdout:");
            std::io::stdout().write_all(&output.stdout)?;
            println!("Stderr:");
            std::io::stdout().write_all(&output.stderr)?;
        }

        match output.status.success() {
            true => info!("Import of {source:?} exited with code: 0."),
            false => error!("Command Failed: [arangoimport {}]", args[..].join(" ")),
        };

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum CollectionType {
    Document = 2,
    Edge = 3,
}

impl TryFrom<u8> for CollectionType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(CollectionType::Document),
            3 => Ok(CollectionType::Edge),
            _ => Err(anyhow!("Invalid collection type.")),
        }
    }
}

pub struct CollectionInfo {
    name: String,
    doc_count: u64,
    kind: CollectionType,
    indexes: Vec<IndexInfo>,
}

impl std::fmt::Display for CollectionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = format!(
            "Collection: {} ({:?}) - {} documents",
            self.name, self.kind, self.doc_count
        );
        for index in self.indexes.iter() {
            output.push_str(&format!("\n * {index}"));
        }
        write!(f, "{}", output)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct IndexInfo {
    name: String,
    id: String,
    kind: String,
    fields: Vec<String>,
}

impl std::fmt::Display for IndexInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

pub struct ArangoEndpoint {
    endpoint: String,
}

impl From<&reqwest::Url> for ArangoEndpoint {
    fn from(value: &reqwest::Url) -> Self {
        Self {
            endpoint: format!(
                "{}://{}",
                match value.scheme() {
                    "http" => "http+tcp",
                    "https" => "http+ssl",
                    _ => value.scheme(),
                },
                value
                    .to_string()
                    .split("://")
                    .last()
                    .expect("Error splitting URL!!!!"),
            ),
        }
    }
}
