use anyhow::Result;
use clap::Parser;
use futures::future::join_all;
use serde_json::json;
use tera::{Context, Tera};

mod schema;
use schema::{Schema, SourceType};

mod cli;
use cli::{Cli, Command};

mod arango;
use arango::ArangoManager;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let schema = schema::SCHEMA
        .get_or_try_init(|| async { Schema::try_from(args.schema_file) })
        .await?;

    match args.command {
        Command::Info { collection_list } => {
            let dbmanager = arango::INSTANCE
                .get_or_try_init(|| async { ArangoManager::try_new(args.url, args.db_name).await })
                .await?;

            let collection_names = match collection_list {
                Some(collections) => collections,
                None => dbmanager.list_collections().await?,
            };
            for name in collection_names {
                if let Some(info) = dbmanager.collection_info(&name).await? {
                    println!("{}", info);
                }
            }
        }
        Command::Init => {
            let dbmanager = arango::INSTANCE
                .get_or_try_init(|| async { ArangoManager::try_new(args.url, args.db_name).await })
                .await?;

            // Create Database
            dbmanager.create_db().await?;

            // Create Collections
            let mut handles = Vec::new();
            let iter = std::iter::zip(
                schema.iter_collection_names(),
                schema.iter_collection_types(),
            );
            for (name, collection_type) in iter {
                handles.push(tokio::spawn(
                    dbmanager.create_collection(name, collection_type),
                ));
            }
            join_all(handles).await; // FIXME: Check errors from async tasks..
        }
        Command::Delete { collection_list } => {
            let dbmanager = arango::INSTANCE
                .get_or_try_init(|| async { ArangoManager::try_new(args.url, args.db_name).await })
                .await?;

            match collection_list {
                // Delete database
                None => {
                    dbmanager.delete_db().await?;
                }
                Some(collection_list) => {
                    let mut handles = Vec::with_capacity(collection_list.len());
                    for name in collection_list {
                        handles.push(tokio::spawn(dbmanager.delete_collection(name)));
                    }
                    join_all(handles).await;
                }
            };
        }
        Command::Truncate { collection_list } => {
            let dbmanager = arango::INSTANCE
                .get_or_try_init(|| async { ArangoManager::try_new(args.url, args.db_name).await })
                .await?;

            let collection_list = match collection_list {
                None => dbmanager.list_collections().await?,
                Some(collection_list) => collection_list,
            };

            let mut handles = Vec::with_capacity(collection_list.len());
            for name in collection_list {
                handles.push(tokio::spawn(async move {
                    dbmanager.truncate_collection(&name).await
                }));
            }
            join_all(handles).await;
        }
        Command::Populate {
            quiet,
            collection,
            file,
        } => {
            let dbmanager = arango::INSTANCE
                .get_or_try_init(|| async { ArangoManager::try_new(args.url, args.db_name).await })
                .await?;

            dbmanager.arangoimport(&collection, file, quiet).await?;
        }
        Command::PopulateAll {
            quiet,
            dynamic_dir,
            static_dir,
            constant_dir,
        } => {
            let dbmanager = arango::INSTANCE
                .get_or_try_init(|| async { ArangoManager::try_new(args.url, args.db_name).await })
                .await?;

            // Construct an iterator with all of the collection information necessary, filtering
            // out based on if the user supplied a base_dir for the specific SourceType (constant,
            // dynamic, or static).
            let base_dirs = schema
                .iter_collection_source_types()
                .map(|src_type| match src_type {
                    SourceType::Constant => &constant_dir,
                    SourceType::Dynamic => &dynamic_dir,
                    SourceType::Static => &static_dir,
                    _ => &None,
                });
            let files = schema.iter_collection_source_files();
            let names = schema.iter_collection_names();
            let collection_items = itertools::izip!(names, base_dirs, files)
                .filter(|(_, base_dir, file)| base_dir.is_some() && file.is_some())
                .collect::<Vec<_>>();

            // Step 1: Delete indexes and truncate collections
            let schema_indexes = schema
                .iter_indexes()
                .map(|(name, _)| name)
                .collect::<Vec<_>>();
            let mut index_handles = Vec::new();
            for (name, _, _) in collection_items.iter() {
                index_handles.push(tokio::spawn(dbmanager.list_indexes_with_id(name)));
            }
            let indexes = join_all(index_handles)
                .await
                .into_iter()
                .filter_map(|r| r.ok())
                .filter_map(|r| r.ok())
                .flatten()
                .collect::<Vec<_>>();
            let mut handles = Vec::new();
            for (name, id) in indexes {
                if schema_indexes.contains(&name.as_str()) {
                    handles.push(tokio::spawn(dbmanager.delete_index(id)));
                }
            }
            join_all(handles).await;

            let mut handles = Vec::new();
            for (name, _, _) in collection_items.iter() {
                handles.push(tokio::spawn(dbmanager.truncate_collection(name)));
            }
            join_all(handles).await;

            // Step 2: Populate
            let mut handles = Vec::new();
            for (name, base_dir, source_file) in collection_items.iter() {
                let base_dir = base_dir.as_ref().unwrap(); // Safe because we filter out None above
                let source_file = source_file.as_ref().unwrap();
                handles.push(tokio::spawn(dbmanager.arangoimport(
                    &name,
                    base_dir.join(source_file),
                    quiet,
                )));
            }
            join_all(handles).await;

            // Step 3: Recreate indexes after populating
            let mut handles = Vec::new();
            for (name, index) in schema.iter_indexes() {
                handles.push(tokio::spawn(dbmanager.create_index(
                    name,
                    json!({"type": index.index_type, "fields": index.fields}),
                )))
            }
            join_all(handles).await; // FIXME: Check errors from async tasks..
        }
        Command::Doc { format } => {
            let context = Context::from_serialize(schema)?;
            let template = match format {
                cli::DocFormat::Html => schema::HTML_TEMPLATE,
                cli::DocFormat::Dot => schema::DOT_TEMPLATE,
                cli::DocFormat::Md => schema::MD_TEMPLATE,
                cli::DocFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(schema)?);
                    return Ok(());
                }
            };

            println!("{}", Tera::one_off(template, &context, true)?);
        }
    }

    Ok(())
}
