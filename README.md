# NODEPP-JWT
A simple JWT implementation in Nodepp

## Example
```cpp
#define SECRET "HELLOWORLDPASS"

#include <nodepp/nodepp.h>
#include <nodepp/json.h>
#include <jwt/jwt.h>

using namespace nodepp;

void onMain() {

    object_t obj ({
        { "user", "EDBC_REPO" },
        { "pass", "123456789" },
        { "payl", "Hello World" }
    });

    auto token = jwt::HS256::encode( json::stringify(obj), SECRET );
    if( jwt::HS256::verify( token, SECRET ) ) { 
        conio::done( "valid token: " ); console::log( token );
        console::log( "payload", jwt::HS256::decode( token ) );
    } else {
        conio::error( "invalid token: " );
        console::log( token );
    }

}
```

## Algorithms
```bash
📌: HS256
📌: HS341
📌: HS512
```

## Compilation
```bash
💻: g++ -o main main.cpp -I ./include ; ./main
```
