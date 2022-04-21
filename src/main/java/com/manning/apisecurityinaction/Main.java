package com.manning.apisecurityinaction;

import java.nio.file.*;

import com.manning.apisecurityinaction.controller.*;
import org.dalesbred.Database;
import org.dalesbred.result.EmptyResultException;
import org.h2.jdbcx.JdbcConnectionPool;
import org.json.*;
import spark.*;
import com.google.common.util.concurrent.*;

import static spark.Spark.*;

public class Main {

    public static void main(String... args) throws Exception {
        
        //Intialize the database with priveleged user
        var datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter", "password");
        var database = Database.forDataSource(datasource);
        createTables(database);

        //Switch to the natter_api_use and recreate the db objects
        datasource = JdbcConnectionPool.create(
            "jdbc:h2:mem:natter", "natter_api_user", "password");

        database = Database.forDataSource(datasource);
        var spaceController = new SpaceController(database);

        var userController =  new UserController(database);

        //Create the rate limiter object and allow just 2 API requests per second
        var rateLimiter = RateLimiter.create(2.0d);

        before((request, response) -> {
            //Check if the rate has been exceeded
            if (!rateLimiter.tryAcquire()){
                //Header identicating the client should retry after 2 seconds
                response.header("Retry-After", "2");
                //Return http response 429 too many requests status
                halt(429);
            }
        });

        before(((request, response) -> {
            if (request.requestMethod().equals("POST") &&
                !"application/json".equals(request.contentType())) {
                    halt(415, new JSONObject().put(
                        "error", "Only application/json supported"
                    ).toString());
                }
        }));
        after((request, response) -> {
            response.type("application/json");
        });

        afterAfter((request, response) -> {

            // Remove the header containing the server type from the response
            response.header("X-XSS-Protection", "0");

            //utf8 to avoid stealing data through JSON response
            response.type("application/json;charset=utf-8");

            //nonsniff to prevent browser guessing the correct Content Type
            response.header("X-Content-Type-Options", "nonsniff");

            //prevent API responses from being loaded in a frame or iframe.
            response.header("X-Frame-Options", "DENY");

            //disable caching
            response.header("Cache-Control","no-store");

            //Tells the browser to ignore suspected XSS attacks as it causes another securtiy attacks.
            response.header("X-XSS-Protection", "0");

            //default-src prevents the response from loading any script
            //frame-ancestors prevents the response being loaded into an iframe
            //sandbox disables scripts and other potentially dangerous content
            response.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox");

            //remove revealing server type in response
            response.header("Server", "");
        });

        before(userController::authenticate);

        post("/spaces", spaceController::createSpace);
        post("/users", userController::registerUser);

        internalServerError(new JSONObject()
            .put("error", "internal server error").toString());
        notFound(new JSONObject()
            .put("error", "not found").toString());

        exception(IllegalArgumentException.class, Main::badRequest); 
        exception(JSONException.class, Main::badRequest);
        exception(EmptyResultException.class, 
            (e, request, response) -> response.status(404));
    }

    private static void createTables(Database database) throws Exception {
        var path = Paths.get(
                Main.class.getResource("/schema.sql").toURI());
        database.update(Files.readString(path));
    }

    private static void badRequest(Exception ex, Request request, Response response) {
        response.status(400);
        //User proper JSON library for all outputs
        //remove the leak of the exception class details by using ex.geytMessage instead of just ex
        response.body(new JSONObject()
            .put("error", ex.getMessage()).toString());
    }
}