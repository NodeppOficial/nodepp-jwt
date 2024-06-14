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

    auto token = jwt::HS348::encode( json::stringify(obj), SECRET );
    if( jwt::HS348::verify( token, SECRET ) ) { 
        conio::done( "valid token: " ); console::log( token );
        console::log( "payload", jwt::HS348::decode( token ));
    } else {
        conio::error( "invalid token: " );
        console::log( token );
    }

}