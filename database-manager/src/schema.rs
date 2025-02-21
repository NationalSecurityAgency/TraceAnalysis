use quick_xml::de::from_str;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::path::PathBuf;
use tokio::sync::OnceCell;

use crate::arango::CollectionType;

// TODO: Should these structs be generated from the schema file?

pub static SCHEMA: OnceCell<Schema> = OnceCell::const_new();

pub static HTML_TEMPLATE: &'static str = include_str!("template.html");
pub static DOT_TEMPLATE: &'static str = include_str!("template.dot");
pub static MD_TEMPLATE: &'static str = include_str!("template.md");

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct Schema {
    #[serde(rename(deserialize = "@version"))]
    pub version: String,
    #[serde(rename(deserialize = "node"), default)]
    pub nodes: Vec<Node>,
    #[serde(rename(deserialize = "edge"), default)]
    pub edges: Vec<Edge>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct Node {
    #[serde(rename(deserialize = "@name"))]
    pub name: String,
    #[serde(rename(deserialize = "@sourcetype"))]
    pub source_type: SourceType,
    #[serde(rename(deserialize = "@sourcefile"))]
    pub source_file: Option<PathBuf>,
    description: String,
    #[serde(rename(deserialize = "attr"), default)]
    pub attributes: Vec<Attribute>,
    #[serde(rename(deserialize = "index"), default)]
    pub indexes: Vec<Index>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct Edge {
    #[serde(rename(deserialize = "@name"))]
    pub name: String,
    #[serde(rename(deserialize = "@sourcetype"))]
    pub source_type: SourceType,
    #[serde(rename(deserialize = "@src"))]
    pub source: String,
    #[serde(rename(deserialize = "@dst"))]
    pub dest: String,
    #[serde(rename(deserialize = "@sourcefile"))]
    pub source_file: Option<PathBuf>,
    pub description: String,
    #[serde(rename(deserialize = "attr"), default)]
    pub attributes: Vec<Attribute>,
    #[serde(rename(deserialize = "index"), default)]
    pub indexes: Vec<Index>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename(deserialize = "attr"))]
pub struct Attribute {
    #[serde(rename(deserialize = "@name"))]
    pub name: String,
    #[serde(rename(deserialize = "@type", serialize = "type"))]
    pub attribute_type: String,
    pub description: String,
    #[serde(rename(deserialize = "join"), default)]
    pub joins: Vec<Join>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct Join {
    #[serde(rename(deserialize = "@table"))]
    pub table: String,
    #[serde(rename(deserialize = "@attr"))]
    pub field: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct Index {
    #[serde(rename(deserialize = "@type", serialize = "type"))]
    pub index_type: IndexType,
    #[serde(rename(deserialize = "field"), default)]
    pub fields: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SourceType {
    Analysis,
    Constant,
    Dynamic,
    Static,
    User,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum IndexType {
    Persistent,
    Skiplist,
    Hash,
}

impl TryFrom<PathBuf> for Schema {
    type Error = anyhow::Error;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        from_str::<Self>(&std::fs::read_to_string(value)?).map_err(anyhow::Error::from)
    }
}

// Helper Methods
impl Schema {
    pub fn iter_collection_names(&self) -> impl Iterator<Item = &str> {
        let node_names = self.nodes.iter().map(|n| n.name.as_str());
        let edge_names = self.edges.iter().map(|e| e.name.as_str());
        node_names.chain(edge_names)
    }

    pub fn iter_collection_types(&self) -> impl Iterator<Item = CollectionType> {
        let node_types = self
            .nodes
            .iter()
            .map(|_| CollectionType::Document)
            .collect::<Vec<_>>();
        let edge_types = self
            .edges
            .iter()
            .map(|_| CollectionType::Edge)
            .collect::<Vec<_>>();
        node_types.into_iter().chain(edge_types)
    }

    pub fn iter_collection_source_types(&self) -> impl Iterator<Item = &SourceType> {
        let node_types = self.nodes.iter().map(|n| &n.source_type);
        let edge_types = self.edges.iter().map(|e| &e.source_type);
        node_types.chain(edge_types)
    }

    pub fn iter_collection_source_files(&self) -> impl Iterator<Item = &Option<PathBuf>> {
        let node_files = self.nodes.iter().map(|n| &n.source_file);
        let edge_files = self.edges.iter().map(|e| &e.source_file);
        node_files.chain(edge_files)
    }

    pub fn iter_indexes(&self) -> impl Iterator<Item = (&str, &Index)> {
        let mut node_indexes = Vec::new();
        for node in self.nodes.iter() {
            for index in node.indexes.iter() {
                node_indexes.push((node.name.as_str(), index));
            }
        }

        let mut edge_indexes = Vec::new();
        for edge in self.edges.iter() {
            for index in edge.indexes.iter() {
                edge_indexes.push((edge.name.as_str(), index));
            }
        }

        node_indexes.into_iter().chain(edge_indexes.into_iter())
    }
}
