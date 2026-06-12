# Folder structure

```
.
├── Db/                  # If relevant from github.com/Skabunkel/db-version
│   ├── main.yml
│   ├── version
│   └── mods
├── crates/
│   └── <crate-name>/
├── src/                 # This folder may or may not exist, it may not be needed.
│   └── <code>
├── .gitignore
├── README.md
└── CLAUDE.md
```

# Code structure

We prefer a combination of `clean architecture` and `vertical slice architecture` to keep the code clean. Each crate should have a well-defined purpose and a single responsibility.

For new dependencies, pick the latest stable version. Keep existing deps current, but don't bump them as part of unrelated work.

Example of code structure:
`App` <- `Infra` <- `Interface`
Sometimes:
`App` <- `Infra` <- `Interface`

`A <- B` reads as "B depends on A". Dependencies follow the arrow and NEVER go the other way.

## App
This is the main application logic. Models and application logic live here.

If the application logic needs to access data or behavior defined in a downstream layer, it defines a trait here and accepts a generic parameter implementing that trait.

We should NOT use `dyn` — we want types validated at compile time. Generics give us monomorphization, no vtable cost, and stronger type-driven errors. Reach for `dyn` only when there is a concrete reason generics can't express the need (e.g. heterogeneous collections).

## Infra
This layer implements the logic for reading from and writing to external sources — for example: filesystem, database, API clients, FTP client, TCP, UDP.
Anything that reads from or writes to an external source goes in this layer.
Infra implements traits defined in the `App` layer.

## Interface
This is the layer where everything comes together. `Interface` depends on the `App` and `Infra` layers.
This is where something interacts with us. Examples include but are not limited to: REST API, message handlers, gRPC, TCP, UDP, and more.

If we have to access information from this layer in the `Infra` or `App` layers, we define a trait in the correct layer and implement it here.

External DTO objects are defined here

NO OTHER LAYER MAY DEPEND ON THIS LAYER.

# Tests

There should be tests that assume success AND tests that assume failure.
Each layer should have well-defined tests where possible.
Tests that interact with external systems should use a test container when possible.


# Important
DO NOT USE Anyhow.
Be restrictive with crates, if you need one ask before pulling it in.


## You can use
Tokio, Axum, Serde, Serde-Json, Sqlx.
The `App` layer can be depend on Tokio.
