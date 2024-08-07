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

    auto token = jwt::HS384::encode( json::stringify(obj), SECRET );
    if( jwt::HS384::verify( token, SECRET ) ) { 
        conio::done( "valid token: " ); console::log( token );
        console::log( "payload", jwt::HS384::decode( token ));
    } else {
        conio::error( "invalid token: " );
        console::log( token );
    }

}