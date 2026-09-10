# ghz scenarios

The current public load surface is API Gateway HTTP. Direct gRPC tests require service addresses and auth metadata for the selected environment. Contract method names must be generated from the current `automatic-system-contracts` checkout; static guessed call templates are deliberately not included.

Use `ghz --proto <current.proto> --call <verified.package.Service.Method> ...` and preserve `ghz.json` under the run directory. The capacity analyzer accepts the raw artifact once a parser for that concrete result is selected.
