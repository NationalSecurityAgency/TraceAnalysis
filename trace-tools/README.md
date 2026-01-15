# Tools

## tm-cli

This is a command-line program for initing a DuckDB representation of the data

```
tm-cli --database-path=/path/to/your/database.db --init --import-static=/path/to/your/static/csvs --import-dynamic=/path/to/your/dynamic/csvs --import-arch=/path/to/traceanalysis/database-manager/data/constants/arch/
```

## tm-api-server

This is a server which proxies JSON-serialized requests to the API library and maintains a persistent connection to the 

```
LD_LIBRARY_PATH=/usr/local/lib tm-api-server --database-path=/path/to/your/database.db --str-index=/path/to/strings.index --st-index=/path/to/spacetime.index
```

It will listen on `localhost:8080`

## tm-q

This is a CLI client for querying the api server:

```
tm-q 
Usage: tm-q <COMMAND>

Commands:
  get-instructions            
  string-search               
  get-modules                 
  get-memory                  
  get-instruction-trace-time  
  get-instruction-trace-pc    
  why                         
  slice                       
  backslice                   
  coverage                    
  min-tick                    
  max-tick                    
  accesses                    
  help                        Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

# Libraries

## `api/tm-api`

This is an API library for accessing information from the database which you extend or upon which you can build other analyses or tools
