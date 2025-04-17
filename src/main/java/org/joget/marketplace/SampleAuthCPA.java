package org.joget.marketplace;

import org.joget.directory.model.User;
import org.joget.plugin.base.DefaultApplicationPlugin;
import org.joget.plugin.base.PluginWebSupport;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.joget.plugin.directory.SecureDirectoryManagerImpl;
import org.joget.workflow.model.dao.WorkflowHelper;
import org.joget.workflow.util.WorkflowUtil;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Key;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.joget.apps.app.service.AppPluginUtil;
import org.joget.apps.app.service.AppUtil;
import org.joget.apps.workflow.security.WorkflowUserDetails;
import org.joget.commons.util.LogUtil;
import org.joget.commons.util.ResourceBundleUtil;
import org.joget.directory.dao.RoleDao;
import org.joget.directory.dao.UserDao;
import org.joget.directory.ext.DirectoryManagerAuthenticatorImpl;
import org.joget.directory.model.Role;
import org.joget.directory.model.service.DirectoryManagerAuthenticator;
import org.joget.directory.model.service.DirectoryManagerProxyImpl;
import org.joget.plugin.base.PluginManager;
import org.json.JSONObject;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

public class SampleAuthCPA extends DefaultApplicationPlugin implements PluginWebSupport {
    private String username;
    private String password;
    private String firstName;
    private String lastName;

    private User user;
    private final static String MESSAGE_PATH = "message/sample-auth-cpa";
    @Override
    public String getName() {
        return AppPluginUtil.getMessage("org.joget.marketplace.SampleAuthCPA.pluginLabel", getClassName(), MESSAGE_PATH);
    }

    @Override
    public String getDescription() {
        return AppPluginUtil.getMessage("org.joget.marketplace.SampleAuthCPA.pluginDesc", getClassName(), MESSAGE_PATH);
    }

    @Override
    public String getVersion() {
        return Activator.VERSION;
    }

    @Override
    public String getLabel() {
        return AppPluginUtil.getMessage("org.joget.marketplace.SampleAuthCPA.pluginLabel", getClassName(), MESSAGE_PATH);
    }

    @Override
    public String getClassName() {
        return getClass().getName();
    }

    @Override
    public String getPropertyOptions() {
        return AppUtil.readPluginResource(getClass().getName(), "/properties/SampleAuthCPA.json", null, true, MESSAGE_PATH);
    }

    public String getUsername() {
        return user.getUsername();
    }
    
    public String getPassword() {
        return user.getPassword();
    }
    
    private void decodeJwt(String jwtToken, String secretKey){
        LogUtil.info(this.getClassName(), "jwtToken = " + jwtToken);
        
        try {
            // Decode and parse the JWT token using Jwts.parserBuilder()
        Key key = Keys.hmacShaKeyFor(secretKey.getBytes());

        // Parse the JWT and extract claims
        Claims claims = Jwts.parserBuilder()  // Create a parser builder
                .setSigningKey(key)           // Set the signing key
                .build()                      // Build the parser
                .parseClaimsJws(jwtToken)     // Parse the JWT
                .getBody();                   // Get the claims body

            // Extract claims
            username = claims.get("username", String.class);  // Custom claim "username"
            password = claims.get("password", String.class);  // Custom claim "password"
            firstName = claims.get("firstName", String.class);  // Custom claim "firstName"
            lastName = claims.get("lastName", String.class);  // Custom claim "firstName"
            String publicToken = claims.get("publicToken", String.class);  // Custom claim "publicToken"
            String subject = claims.getSubject();  // Standard claim "subject"
            long expiration = claims.getExpiration().getTime();  // Expiration time

            // Print the decoded values
            System.out.println("Decoded JWT:");
            System.out.println("Username: " + username);
            System.out.println("Password: " + password);
            System.out.println("Public Token: " + publicToken);
            System.out.println("Subject: " + subject);
            System.out.println("Expiration Time: " + expiration);
            
        } catch (Exception e) {
            System.out.println("Invalid JWT or decoding error: " + e.getMessage());
        }
    }

    @Override
    public Object execute(Map properties) {
        return null;
    }

    @Override
    public void webService(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        LogUtil.info(this.getClassName(), "test");
        DirectoryManagerProxyImpl dm = (DirectoryManagerProxyImpl) AppUtil.getApplicationContext().getBean("directoryManager");

        // The same secret key used during encoding (hard-coded).
        String secretKey = "3P1dcB3L+Um4py8DYSw73T7iY/GED/P/ShJa6tPVvRE=";

        // Create new user if user does not exist (hard-coded)
        boolean userProvisioningEnabled = true;
        
        String token = request.getParameter("token");
        
        if(token == null){
            StringBuilder jsonPayload = new StringBuilder();
            try (BufferedReader reader = request.getReader()){
                String line;
                while ((line = reader.readLine()) != null) {
                    jsonPayload.append(line);
                }
            }
            
            //Parse the jsonPayload
            JSONObject jsonObject = new JSONObject(jsonPayload.toString());
            token = jsonObject.getString("token");
        }
        
        decodeJwt(token, secretKey);
        
        if (username == null) {
            response.sendRedirect(request.getContextPath() + "/web/login?login_error=1");
            return;
        }

        user = dm.getUserByUsername(username);
        if (user == null && userProvisioningEnabled) {

            user = new User();
            user.setUsername(username);
            user.setId(username);
            user.setFirstName(firstName);
            user.setLastName(lastName);
            user.setTimeZone("0");
            user.setActive(1);
            LogUtil.info(this.getClassName(), "username=" + username);

             // set role
            RoleDao roleDao = (RoleDao) AppUtil.getApplicationContext().getBean("roleDao");
            Set roleSet = new HashSet();
            Role r = roleDao.getRole("ROLE_USER");
            if (r != null) {
                roleSet.add(r);
            }
            user.setRoles(roleSet);
            // add user
            UserDao userDao = (UserDao) AppUtil.getApplicationContext().getBean("userDao");
            userDao.addUser(user);
        }
        
        try 
        {
            // verify license
            PluginManager pluginManager = (PluginManager) AppUtil.getApplicationContext().getBean("pluginManager");
            DirectoryManagerAuthenticator authenticator = (DirectoryManagerAuthenticator) pluginManager.getPlugin(DirectoryManagerAuthenticatorImpl.class.getName());
            boolean authenticated = false;
            if (user != null) {
                authenticated = authenticator.authenticate(dm, user.getUsername(), user.getPassword());
            }
            LogUtil.info(getClassName(), "Authenticated:" + authenticated);
            // get authorities
            Collection<Role> roles = dm.getUserRoles(username);
            List<GrantedAuthority> gaList = new ArrayList<>();
            if (roles != null && !roles.isEmpty()) {
                for (Role role : roles) {
                    GrantedAuthority ga = new SimpleGrantedAuthority(role.getId());
                    gaList.add(ga);
                }
            }

            // login user
            UserDetails details = new WorkflowUserDetails(user);
            UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(username, "", gaList);
            result.setDetails(details);
            SecurityContextHolder.getContext().setAuthentication(result);
            
            
            // add audit trail
            WorkflowHelper workflowHelper = (WorkflowHelper) AppUtil.getApplicationContext().getBean("workflowHelper");
            workflowHelper.addAuditTrail(this.getClass().getName(), "authenticate", "Authentication for user " + username + ": " + true);

            // redirect
            SavedRequest savedRequest = new HttpSessionRequestCache().getRequest(request, response);
            String savedUrl = "";
            if (savedRequest != null) {
                savedUrl = savedRequest.getRedirectUrl();
            } else {
                savedUrl = request.getContextPath();
            }
            response.sendRedirect(savedUrl);
        } catch (IOException | RuntimeException ex) {
            LogUtil.error(getClass().getName(), ex, "Error in custom login");
            request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", new Exception(ResourceBundleUtil.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials")));
            String url = request.getContextPath() + "/web/login?login_error=1";
            response.sendRedirect(url);
        }
    }
}
