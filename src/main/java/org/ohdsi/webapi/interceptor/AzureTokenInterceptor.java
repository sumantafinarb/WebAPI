package org.ohdsi.webapi.interceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

public class AzureTokenInterceptor extends HandlerInterceptorAdapter {

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String token = request.getHeader("Auth");
        if (token == null || !validateTokenWithMicrosoftGraph(token)) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
            return false;
        }
        return true;
    }

    private boolean validateTokenWithMicrosoftGraph(String token) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet getRequest = new HttpGet("https://graph.microsoft.com/v1.0/me");
            getRequest.setHeader("Authorization", "Bearer " + token);
            getRequest.setHeader("Content-Type", "application/json");

            CloseableHttpResponse httpResponse = client.execute(getRequest);
            HttpEntity entity = httpResponse.getEntity();
            if (entity != null) {
                return httpResponse.getStatusLine().getStatusCode() == 200;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
