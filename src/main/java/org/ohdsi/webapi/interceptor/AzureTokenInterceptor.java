package org.ohdsi.webapi.interceptor;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

@Provider
@Priority(Priorities.AUTHENTICATION)
public class AzureTokenInterceptor implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext requestContext) {
        String token = requestContext.getHeaderString("Auth");
        if (token == null || !validateTokenWithMicrosoftGraph(token)) {
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    private boolean validateTokenWithMicrosoftGraph(String token) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet getRequest = new HttpGet("https://graph.microsoft.com/v1.0/me");
            getRequest.setHeader("Authorization", "Bearer " + token);
            getRequest.setHeader("Content-Type", "application/json");

            try (CloseableHttpResponse httpResponse = client.execute(getRequest)) {
                return httpResponse.getStatusLine().getStatusCode() == 200;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
