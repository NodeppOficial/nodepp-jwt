#define SECRET "HELLOWORLDPASS"

#include <nodepp/nodepp.h>
#include <nodepp/json.h>
#include <jwt.h>

using namespace nodepp;

void onMain() {

    object_t obj ({
        { "user", "EDBC_REPO" },
        { "pass", "123456789" },
        { "payl", "Hello World" }
    });

    auto token = jwt::XOR::encode( json::stringify(obj), SECRET );
    
    if( jwt::XOR::verify( token, SECRET ) ) { 
        conio::done( "valid token: " ); console::log( token );
        console::log( "payload", jwt::XOR::decode( token ));
    } else {
        conio::error( "invalid token: " );
        console::log( token );
    }

}