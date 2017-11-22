package org.gluu.fortressui.controller;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;

import java.security.Security;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.codehaus.groovy.runtime.powerassert.SourceText;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.xdi.oxauth.client.JwkClient;
import org.xdi.oxauth.client.TokenClient;
import org.xdi.oxauth.client.TokenRequest;
import org.xdi.oxauth.client.TokenResponse;
import org.xdi.oxauth.model.common.GrantType;
import org.xdi.oxauth.model.crypto.signature.ECDSAPublicKey;
import org.xdi.oxauth.model.crypto.signature.RSAPublicKey;
import org.xdi.oxauth.model.crypto.signature.SignatureAlgorithm;
import org.xdi.oxauth.model.jws.RSASigner;
import org.xdi.oxauth.model.jwt.Jwt;
import org.xdi.oxauth.model.jwt.JwtClaimName;
import org.xdi.oxauth.model.jwt.JwtHeader;
import org.xdi.oxauth.model.jwt.JwtHeaderName;
import org.xdi.oxd.client.CommandClient;
import org.xdi.oxd.common.Command;
import org.xdi.oxd.common.CommandResponse;
import org.xdi.oxd.common.CommandType;
import org.xdi.oxd.common.params.*;
import org.xdi.oxd.common.response.*;

@Controller
@RequestMapping("/")
public class OxdConsumer {

	@Value("${oxd.host}")
	private String oxdHost ;

	@Value("${oxd.port}")
	private int oxdPort;

	@Value("${oxd.token.file}")
	private String oxdTokenContainer ;

	@GetMapping("/")
	private String index() {
		return "redirect:/check";
	}
	
	@GetMapping("/rpt")
	private ResponseEntity<?> getRpt(HttpServletRequest req) {
		System.out.println("rpt call");
		
		CommandClient client = null;
		HttpSession session = req.getSession(true);
		
		try {
			client = new CommandClient("localhost", 8099);
			String oxdId = "";
			RpGetRptParams params = new RpGetRptParams();
			if(session.getAttribute("oxdId") != null){
				oxdId = (String) session.getAttribute("oxdId");
			}else {
				oxdId = getOxdToken();
				session.setAttribute("oxdId", oxdId);
			}
			
			
			params.setOxdId(oxdId);

			String recivedAAt = (String)session.getAttribute("aat");
			//params.setAat(recivedAAt); --error
			params.setRpt(recivedAAt);
			Command command = new Command(CommandType.RP_GET_RPT).setParamsObject(params);

			CommandResponse response = client.send(command);

			RpGetRptResponse rptResponse = response.dataAsResponse(RpGetRptResponse.class);
			System.out.println("RPT Response=====>"+rptResponse);
			
			JsonResponseRpt json = new JsonResponseRpt();
			json.setOxdId(oxdId);
			json.setRptToken(rptResponse.getRpt());
			
			return new ResponseEntity<>(json, HttpStatus.OK);

		} catch (IOException ioE) {
			ioE.printStackTrace();

		} finally {
			CommandClient.closeQuietly(client);
		}
		return new ResponseEntity<>("", HttpStatus.INTERNAL_SERVER_ERROR);
	}
	@GetMapping("/all")
	@ResponseBody
	private  String all() {
		return "all";

	}

	@GetMapping("/logout")
	private ResponseEntity<?> logout(HttpServletRequest request) {
		HttpStatus status = HttpStatus.OK;
		String message = "user logged out";
		return new ResponseEntity<>(message, status);
	}

	@GetMapping("/loginSuccess")
	private void loginSuccess(HttpServletRequest request ,HttpServletResponse response) throws ServletException, IOException {
	
		HttpSession session = request.getSession(true);
		String url= request.getRequestURL()+"?"+request.getQueryString();//fetch the query String
		System.out.println("After Authentication Code Flow the URL is  => "+url);
		/*Get all request parameters
        while (request.getParameterNames().hasMoreElements()) {
			Object element = request.getParameterNames().nextElement();
			System.out.println(element.toString());
			// process element
		}      OR
		if(request.getParameterMap().containsKey("code")){
			code = request.getParameter("code");
			System.out.println(code);
		}*/
		/* if(session.getAttribute("oxdId") != null){
			oxdId = (String) session.getAttribute("oxdId");
		} OR */
		String oxdId = getOxdToken();
		// if implicit flow then we get tokens after sendRedirect->url -in such case we need an ajax call or
		// client call to hit and give us back what(tokens) is coming as fragment identifier
		//The authorisation code could be expired. The life time can be configured in oxAuth configuration entry: "authorizationCodeLifetime"
		//The authorisation code can be used just once.
		String code=getMatchingString(url, "code=(.+?)&");
		String state=getMatchingString(url, "state=(.+?)&");
		String sessionState=getMatchingString(url, "session_state=(.+?)&");//if normal state does not work in Token call
		System.out.println("Entering=> oxdId-"+oxdId+"----code-"+code+"----state-"+state+"----"+"----session_state-"+sessionState);
		if(!(code.isEmpty()) && !(state.isEmpty())){
			CommandClient client = null;
			try {
			    client = new CommandClient("localhost", 8099);
			    final GetTokensByCodeParams commandParams = new GetTokensByCodeParams();
				commandParams.setOxdId(oxdId);
			    commandParams.setCode(code);
			    commandParams.setState(state);
			    final Command command = new Command(CommandType.GET_TOKENS_BY_CODE).setParamsObject(commandParams);
			    final GetTokensByCodeResponse resp = client.send(command).dataAsResponse(GetTokensByCodeResponse.class);
				System.out.println("GetTokensByCodeRequest ==>"+commandParams.toString());
			    System.out.println("GetTokensByCodeResponse ==>"+resp.toString());
			    /*//directly hit the rest end point - should end with /token like one below
				String tokenUrl = "https://gluuadmin.enetdefender.com/oxauth/restv1/token";
				String redirectUri = "https://manoj:8888/loginSuccess";
				TokenClient tokenClient = new TokenClient(tokenUrl);
				//many methods in tokenclient. in place of execResourceOwnerPasswordCredentialsGrant
				TokenResponse tkResponse = tokenClient.execResourceOwnerPasswordCredentialsGrant("admin", "s3cr3t", "openid", "admin", "s3cr3t");*/
			    if(resp.getIdToken()!=null && resp.getAccessToken()!=null)
				System.out.println("idToken :- "+ resp.getIdToken()+" -------- AccessToken - "+resp.getAccessToken()+" -------- RefreshToken - "+resp.getRefreshToken());
			    String idToken=resp.getIdToken();
				String accessT=resp.getAccessToken();
			    //Decode the header and payload via that API but having trouble to validate the token -- on way you can extract iss and validate it with your server name
                System.out.println("------------ Decode IdToken JWT ------------");
				String[] split_string = idToken.split("\\.");
				String base64EncodedHeader = split_string[0];
				String base64EncodedBody = split_string[1];
				String base64EncodedSignature = split_string[2];
				Base64 base64Url = new Base64(true);
				System.out.println("~~~~~~~~~ ID Token Header ~~~~~~~");
				String header = new String(base64Url.decode(base64EncodedHeader));
				System.out.println("ID Token JWT Header : " + header);
				System.out.println("~~~~~~~~~ ID Token Body ~~~~~~~");
				String body = new String(base64Url.decode(base64EncodedBody));
				System.out.println("ID Token JWT Body : "+body.toString());
				System.out.println("~~~~~~~~~ ID Token Signature ~~~~~~~");
				String signature = new String(base64Url.decode(base64EncodedSignature));
				//System.out.println("ID Token JWT Signature : "+signature.toString());
				session.setAttribute("idt", resp.getIdToken());
			    session.setAttribute("authenticationt", resp.getAccessToken());
				session.setAttribute("refresht", resp.getRefreshToken());
				//validate jwt token - if validation exception occurs -- dont allow to make api call and raise jwt exception - should be the first call while making an API call
				// Parse token
				Jwt jwt = Jwt.parse(idToken);
				// Validate signature RS256, RS384, RS512 - check alg [header]
				RSAPublicKey publicKey = JwkClient.getRSAPublicKey("https://gluuadmin.enetdefender.com/oxauth/restv1/jwks",jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID));
					//System.out.println("public key is "+publicKey);
				Security.addProvider(new BouncyCastleProvider());//otherwise no such provider BC
				RSASigner rsaSigner = new RSASigner(SignatureAlgorithm.RS256, publicKey);
				boolean validSignature = rsaSigner.validate(jwt);
				System.out.println("#########################"+validSignature+"#########################");
				if(validSignature){
					//display the information contained in idToken
					// Extract header values
					String kid = jwt.getHeader().getClaimAsString(JwtHeaderName.KEY_ID);
					String type = jwt.getHeader().getClaimAsString(JwtHeaderName.TYPE);
					String algorithm = jwt.getHeader().getClaimAsString(JwtHeaderName.ALGORITHM);
					//String jku = jwt.getHeader().getClaimAsString(JwtHeaderName.JSON_WEB_KEY); - not in our Gluu
					// Extract claims - or Body
					String issuer = jwt.getClaims().getClaimAsString(JwtClaimName.ISSUER);
					String audience = jwt.getClaims().getClaimAsString(JwtClaimName.AUDIENCE);
					Date expirationTime = jwt.getClaims().getClaimAsDate(JwtClaimName.EXPIRATION_TIME);
					Date issuedAt = jwt.getClaims().getClaimAsDate(JwtClaimName.ISSUED_AT);
					Date authTime = jwt.getClaims().getClaimAsDate(JwtClaimName.AUTHENTICATION_TIME);
					String atHash = jwt.getClaims().getClaimAsString(JwtClaimName.ACCESS_TOKEN_HASH);
					String openIdConnectVersion = jwt.getClaims().getClaimAsString("oxOpenIDConnectVersion");
					//OR
					String openIdConnectVersionAnotherWay = jwt.getClaims().getClaimAsString(JwtClaimName.OX_OPENID_CONNECT_VERSION);
					String sub = jwt.getClaims().getClaimAsString(JwtClaimName.SUBJECT_IDENTIFIER);
					String userName = jwt.getClaims().getClaimAsString(JwtClaimName.USER_NAME);
					String principal=jwt.getClaims().getClaimAsString(JwtClaimName.PRINCIPAL);
					String address=jwt.getClaims().getClaimAsString(JwtClaimName.ADDRESS);
					String name=jwt.getClaims().getClaimAsString(JwtClaimName.NAME);
					String email=jwt.getClaims().getClaimAsString(JwtClaimName.EMAIL);
					String phone=jwt.getClaims().getClaimAsString(JwtClaimName.PHONE_NUMBER);

					System.out.println("My Params => "+kid+"-"+type+"-"+algorithm+"-"+issuer+"-"+audience+"-"+expirationTime+"-"+issuedAt+"-"+authTime+
							"-"+atHash+"-"+openIdConnectVersion+"-"+openIdConnectVersionAnotherWay+"-"+sub+"-"+userName+"-"+principal+"-"+name+"-"+email+"-"+phone+"-"+address);
					/*JwtToken jwtToken = new JwtToken(accessToken);

					jwtToken.getType();
					jwtToken.getAlgorithm();
					jwtToken.getJsonWebKeyUrl();
					jwtToken.getKeyId();
					jwtToken.getExpirationTime();
					jwtToken.getIssuedAt();
					jwtToken.getIssuer();
					jwtToken.getUserId();
					jwtToken.getAudience();
					jwtToken.getOxInum();
					jwtToken.getOxValidationUri();
					jwtToken.getOxOpenIdConnectVersion();*/

					//String oxInum = jwt.getClaims().getClaimAsString("oxInum");
					//String oxValidationUri = jwt.getClaims().getClaimAsString("oxValidationUri");
					// JwtClaimName.PRINCIPAL // PROFILE - just like spring - you need to enable claims first in your open id connect provider
                    //Get user Claims
					GetUserInfoParams params = new GetUserInfoParams();
					params.setOxdId(oxdId);
					params.setAccessToken(accessT);
					final Command command1 = new Command(CommandType.GET_USER_INFO).setParamsObject(params);
					GetUserInfoResponse getUserInfoResponse = client.send(command1).dataAsResponse(GetUserInfoResponse.class);;
					System.out.println("USER CLAIMS Response==>"+getUserInfoResponse.toString());
				}
			} catch (Exception ex) {
				System.out.println("Exception From GetTokensByCodeCall ##### =>" + ex.getCause()+"--"+ex.getLocalizedMessage());
			} finally {
			    CommandClient.closeQuietly(client);
			}
		}
		request.getRequestDispatcher("/checkAccess").forward(request, response);
	}
	
	@GetMapping("/check")
	private ResponseEntity<?> checkAccessTestResourcePage(HttpServletRequest request,HttpServletResponse response) throws Exception {
		HttpSession session = request.getSession(true);
		String oxdId = getOxdToken();
		String sessionOxdId = (String) session.getAttribute("oxdId");
		if (!oxdId.equals(sessionOxdId)) {
			//session.removeAttribute("code");
			session.setAttribute("oxdId", getOxdToken());
		}
		/*if (session.getAttribute("code") != null) {
			session.removeAttribute("code");
			//request.getRequestDispatcher("/loginSuccess").forward(request, response);
		}
		if (session.getAttribute("state") != null) {
			session.removeAttribute("state");
		}*/
		if (session.getAttribute("code") != null) {
			request.getRequestDispatcher("/loginSuccess").forward(request, response);
		} else {
			String url = getAuthenticationUrl(oxdId);
			//URL urlToHit = new URL(getAuthenticationUrl(oxdId));
			if (url != null) {
				System.out.println("url --> " + url);
			}
			/*try {
				BufferedReader br = new BufferedReader(new InputStreamReader(urlToHit.openStream()));
				String strTemp = "";
				while (null != (strTemp = br.readLine())) {
					System.out.println("Str###################################"+strTemp);
				}
			} catch (Exception ex) {
				System.out.println(ex.getMessage()+"ex");
				ex.printStackTrace();
			}*/
			//response.sendRedirect(url);
			//make a new call with the authentication url fetched as in SOP above and then
			//forward it to new function /getIdToken and set somewhere or write in a file or in session
			//OR below lines till } of condition if url!=null
			//String state=getMatchingString(url, "state=(.+?)&");
			//String code=getMatchingString(url, "nonce=(.+?)&");
				/*try {
					String tokenUrl = "https://gluuadmin.enetdefender.com/oxauth/restv1/token";
					String redirectUri = "https://manoj:8888/loginSuccess";
					TokenClient tokenClient = new TokenClient(tokenUrl);
					TokenResponse tkResponse = tokenClient.execAuthorizationCode(code, redirectUri, "admin", "admin");
					//tokenClient.setRequest(new TokenRequest(GrantType.RESOURCE_OWNER_PASSWORD_CREDENTIALS));
					// TokenResponse tkResponse = tokenClient.execResourceOwnerPasswordCredentialsGrant("admin","s3cr3t","openid","","");
					System.out.println(tkResponse.toString());
					String accessToken1 = tkResponse.getAccessToken();
					String idToken = tkResponse.getIdToken();
					System.out.println(accessToken1 + "---" + idToken);
				}catch (Exception ex){
					System.out.println(ex.getLocalizedMessage());
					ex.printStackTrace();}*/
		//	request.setAttribute("state",state);
		//request.setAttribute("code",code);
		//request.getRequestDispatcher("/loginSuccess").forward(request, response);*/
					/*CommandClient client = null;
					try {
						client = new CommandClient("localhost", 8099);
						final GetTokensByCodeParams commandParams = new GetTokensByCodeParams();
						commandParams.setOxdId(oxdId);
						commandParams.setCode(code);
						commandParams.setState(state);
						final Command command = new Command(CommandType.GET_TOKENS_BY_CODE).setParamsObject(commandParams);
						System.out.println("GetTokensByCodeParams request =>"+command.getParams());
						final GetTokensByCodeResponse resp = client.send(command).dataAsResponse(GetTokensByCodeResponse.class);
						System.out.println("resp=>" + resp);
						String idToken = resp.getIdToken();
						String accessToken = resp.getAccessToken();
						System.out.println(idToken + " - " + accessToken);
						System.out.println("AAT :- " + accessToken);
						session.setAttribute("aat", accessToken);
					} finally {
						CommandClient.closeQuietly(client);
					}*/
			//String credentials = "TestGAPIClient1"+ ":" + "Test123";
			//String tokenUrl = "https://gluuadmin.enetdefender.com/oxauth/seam/resource/restv1/oxauth/token";
			/*String tokenUrl ="https://gluuadmin.enetdefender.com/oxauth/restv1/token";
			String redirectUri= "https://manoj:8888/loginSuccess";
			TokenClient tokenClient = new TokenClient(tokenUrl);
			TokenResponse tkResponse = tokenClient.execAuthorizationCode(code,redirectUri,"TestGAPIClient1", "Test123");
			String accessToken1 = tkResponse.getAccessToken();
			String idToken = tkResponse.getIdToken();
			System.out.println(accessToken1+"---"+idToken);*/
			//request.getSession().setAttribute("code",code);
            //request.getSession().setAttribute("state", state);
           response.sendRedirect(url);
		}
		return new ResponseEntity<>(HttpStatus.OK);
		}

	
	@GetMapping("/checkAccess")
	private String checkAccess() {
		/*CommandClient client = null;
		try {
			client = new CommandClient(host, port);

			final RegisterSiteResponse site = RegisterSiteTest.registerSite(client, opHost, redirectUrl);
			final GetTokensByCodeResponse tokens = requestTokens(client, site, userId, userSecret);

			GetUserInfoParams params = new GetUserInfoParams();
			params.setOxdId(site.getOxdId());
			params.setAccessToken(tokens.getAccessToken());

			final GetUserInfoResponse resp = client.send(new Command(CommandType.GET_USER_INFO).setParamsObject(params)).dataAsResponse(GetUserInfoResponse.class);
		} finally {
			CommandClient.closeQuietly(client);
		}

*/		return "checkaccess";

	}
	
	
	public String getAuthenticationUrl(String oxdId) throws IOException{
		CommandClient client = null;
		String url = "";
		try {
			client = new CommandClient("localhost", 8099);
			GetAuthorizationUrlParams commandParams = new GetAuthorizationUrlParams();
			commandParams.setOxdId(oxdId);
			//Map<String,String> amap=new HashMap<>();
			//amap.put("client_")
			//commandParams.set
			Command command = new Command(CommandType.GET_AUTHORIZATION_URL).setParamsObject(commandParams);

			GetAuthorizationUrlResponse resp = client.send(command).dataAsResponse(GetAuthorizationUrlResponse.class);
			url = resp.getAuthorizationUrl();
		} catch (IOException e) {
			throw e;
		}
		finally {
			CommandClient.closeQuietly(client);
		}
		return url;
	}

	public static String getMatchingString(String stringToBeSearched, String regexSearchPattern) {
		Matcher m= Pattern.compile(regexSearchPattern).matcher(stringToBeSearched);
		String result=null;
		if(m.find()) {
			result=m.group(1).trim();
		}
		return result;
	}
	public String getOxdToken(){
		String oxdToken = "";	
		try{
			FileReader reader = new FileReader(oxdTokenContainer);
			char[] oxdTokenChar = new char[36]; 
			reader.read(oxdTokenChar);
			oxdToken = new String(oxdTokenChar);
			reader.close();
		}catch (Exception e) {
			e.printStackTrace();
		}
		return oxdToken;

	}
	
	class JsonResponseRpt{
		String rptToken;
		String oxdId;
		public String getRptToken() {
			return rptToken;
		}
		public void setRptToken(String rptToken) {
			this.rptToken = rptToken;
		}
		public String getOxdId() {
			return oxdId;
		}
		public void setOxdId(String oxdId) {
			this.oxdId = oxdId;
		}
		
	}
}
