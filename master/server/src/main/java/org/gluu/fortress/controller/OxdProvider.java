package org.gluu.fortress.controller;

import java.io.FileWriter;

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.xdi.oxauth.model.common.AuthenticationMethod;
import org.xdi.oxauth.model.common.GrantType;
import org.xdi.oxauth.model.common.ResponseType;
import org.xdi.oxd.client.CommandClient;
import org.xdi.oxd.common.Command;
import org.xdi.oxd.common.CommandType;
import org.xdi.oxd.common.params.RegisterSiteParams;
import org.xdi.oxd.common.params.RpGetRptParams;
import org.xdi.oxd.common.params.RsCheckAccessParams;
import org.xdi.oxd.common.params.RsProtectParams;
import org.xdi.oxd.common.response.RegisterSiteResponse;
import org.xdi.oxd.common.response.RsCheckAccessResponse;
import org.xdi.oxd.rs.protect.Jackson;
import org.xdi.oxd.rs.protect.RsResourceList;

import com.google.common.collect.Lists;

//This class is resource provider or server class

@RestController
@CrossOrigin
@RequestMapping("/")
public class OxdProvider {

	@Value("${rsProtect}")
	private String rsProtect;

	@Value("${oxd.host}")
	private String oxdHost ;

	@Value("${oxd.port}")
	private int oxdPort;

	@Value("${op.host}")
	private String opHost ;

	@Value("${oxd.token.file}")
	private String oxdTokenContainer ;


	/*
	 * This method perform 3 Task
	 * 1 - Registering the site
	 * 2 - Protecting the resource
	 * 3 - Writing generated oxd id in file for further use (needs to do some refracting for oxd token sharing)
	 */

	@GetMapping("/oxdId")
	private ResponseEntity<?> oxdId(HttpServletRequest request) {
		CommandClient client = null;

		try {
			client = new CommandClient("localhost", 8099);
			RegisterSiteParams commandParams = new RegisterSiteParams();
			commandParams.setOpHost("gluuadmin.enetdefender.com");
			commandParams.setAuthorizationRedirectUri("https://manoj:8888/loginSuccess");
			commandParams.setScope(Lists.newArrayList("openid","profile","email","address","clientinfo","permission","phone","user_name","uma_protection"));
			commandParams.setResponseTypes(Lists.newArrayList(ResponseType.CODE.getValue()));
			commandParams.setGrantType(Lists.newArrayList(GrantType.AUTHORIZATION_CODE.getValue()));
			commandParams.setAcrValues(Lists.newArrayList("auth_ldap_server"));
			//commandParams.setClientId("manoj");
			commandParams.setClientName("TAPSClient");
			//commandParams.setClientSecret("mshori");
			//commandParams.setTrustedClient(Boolean.TRUE);
			//commandParams.setClientId("admin");
			//commandParams.setClientName("admin");
		    //commandParams.setClientSecret("s3cr3t");
			//commandParams.setClientTokenEndpointAuthMethod(AuthenticationMethod.CLIENT_SECRET_BASIC.toString());
			//commandParams.setClientLogoutUri(Lists.newArrayList("https://localhost:9999/logout"));
				//Any one of below 2 is working for redirectURI configuration
			// commandParams.setRedirectUris(Lists.newArrayList("https://localhost:9099/api/resource"));//your conf
			//commandParams.setRedirectUris(Lists.newArrayList("https://localhost:8888/all"));
			//commandParams.setAuthorizationRedirectUri("https://manoj:8888/loginSuccess");//https://manoj:8888/loginSuccess or "https://facebook.com"- or your redirect url
			//commandParams.setRedirectUris(Lists.newArrayList("https://localhost:8888/all"));
			//commandParams.setPostLogoutRedirectUri("https://localhost:8888/all");
			//commandParams.setAcrValues(Lists.newArrayList("auth_ldap_server"));
			//"which all scope's claims to be included in JWT - need to enable some of them"

			//commandParams.setScope(Lists.newArrayList("openid","profile", "uma_protection", "uma_authorization"));
			//commandParams.setResponseTypes(Lists.newArrayList(ResponseType.CODE.getValue(),ResponseType.ID_TOKEN.getValue(), ResponseType.TOKEN.getValue()));
			//commandParams.setGrantType(Lists.newArrayList(GrantType.AUTHORIZATION_CODE.getValue()));
			//commandParams.setGrantType(Lists.newArrayList(GrantType.AUTHORIZATION_CODE.getValue(), GrantType.CLIENT_CREDENTIALS.getValue(), GrantType.IMPLICIT.getValue(),GrantType.OXAUTH_UMA_TICKET.getValue()));
			Command command = new Command(CommandType.REGISTER_SITE).setParamsObject(commandParams);
			System.out.println("Register Site REQUEST => "+command.getParams());
			RegisterSiteResponse site = client.send(command).dataAsResponse(RegisterSiteResponse.class);
			System.out.println("Register Site RESPONSE => "+site.toString());
			//protect(client, site.getOxdId());--rs protect
			request.getSession(true).setAttribute("oxdId", site.getOxdId());
			writeOxdToken(site.getOxdId());
			return new ResponseEntity<>("Resource is Protected", HttpStatus.OK);
		} catch (IOException ioE) {
            System.out.println(ioE.getCause());
			System.out.println(ioE.getLocalizedMessage());
			ioE.printStackTrace();
			return new ResponseEntity<>("Error In Resource Protection", HttpStatus.INTERNAL_SERVER_ERROR);

		} finally {
			CommandClient.closeQuietly(client);
		}
	}

	@GetMapping("/api/checkAccess")
	public ResponseEntity<?> checkResourceAccess(@RequestParam("oxdId") String oxdId,@RequestParam("rpt") String rpt,
												 @RequestParam("path") String path,@RequestParam("httpMethod") String httpMethod) {
		CommandClient client = null;
		try{
			client = new CommandClient(oxdHost, oxdPort);
			RsCheckAccessResponse response = checkAccess(client, oxdId, "", path, httpMethod);
			if(response != null ){
				String ticket = response.getTicket();
				authorizeRpt(client, oxdId, rpt, ticket);
				response = checkAccess(client ,oxdId, rpt, path, httpMethod);
				if(response.getAccess().equals("denied")){
					return new ResponseEntity<>("Access to Resource Request is Denied.", HttpStatus.OK);
				} else if(response.getAccess().equals("granted")){
					return new ResponseEntity<>("Access to Resource Request is Granted.", HttpStatus.OK);
				}
			}
			else {
				return new ResponseEntity<>("Access to Resource Request is Denied.", HttpStatus.OK);
			}
		}
		catch(IOException exception){
			exception.printStackTrace();
		}
		finally{
			CommandClient.closeQuietly(client);
		}
		return new ResponseEntity<>("Bad Request", HttpStatus.INTERNAL_SERVER_ERROR);
	}

	//Test resource(this resource will be protected)
	@GetMapping("/api/resource")
	private ResponseEntity<?> resource(HttpServletRequest request) {
		HttpStatus status = HttpStatus.OK;
		String message = "Test Resources";
		return new ResponseEntity<>(message, status);
	}

	//protecting resource
	public void protect(CommandClient client,String oxdId) throws IOException {
		final RsProtectParams commandParams = new RsProtectParams();
		commandParams.setOxdId(oxdId);
		commandParams.setResources(resourceList().getResources());

		final Command command = new Command(CommandType.RS_PROTECT)
				.setParamsObject(commandParams);

		client.send(command);
	}

	//checking access of a resource
	public RsCheckAccessResponse checkAccess(CommandClient client,String oxdId,String rpt, String path, String httpMethod) {

		RsCheckAccessParams params = new RsCheckAccessParams();
		params.setOxdId(oxdId);
		params.setPath(path);
		params.setRpt(rpt);
		params.setHttpMethod(httpMethod);
		return client.send(new Command(CommandType.RS_CHECK_ACCESS, params)).dataAsResponse(RsCheckAccessResponse.class);

	}

	//authorizing rpt Token
	public void authorizeRpt(CommandClient client,String oxdId, String rpt, String ticket) {

		final RpGetRptParams params = new RpGetRptParams();
		params.setOxdId(oxdId);
		//params.setRpt(rpt);
		//params.setTicket(ticket);
		client.send(new Command(CommandType.RP_GET_RPT, params));

	}

	public void writeOxdToken(String oxdToken){
		try{
			FileWriter writer = new FileWriter(oxdTokenContainer);
			writer.write(oxdToken);
			writer.close();
		}catch (Exception e) {
			e.printStackTrace();
		}
	}

	private RsResourceList resourceList() throws IOException {
		rsProtect = StringUtils.replace(rsProtect, "'", "\"");
		return Jackson.createJsonMapper().readValue(rsProtect, RsResourceList.class);
	}

}

//ORIGINAL File
//package org.gluu.fortress.controller;
//
//import java.io.FileWriter;
//
//import java.io.IOException;
//
//import javax.servlet.http.HttpServletRequest;
//
//import org.apache.commons.lang.StringUtils;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.CrossOrigin;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//import org.springframework.web.bind.annotation.RestController;
//import org.xdi.oxauth.model.common.GrantType;
//import org.xdi.oxauth.model.common.ResponseType;
//import org.xdi.oxd.client.CommandClient;
//import org.xdi.oxd.common.Command;
//import org.xdi.oxd.common.CommandType;
//import org.xdi.oxd.common.params.RegisterSiteParams;
//import org.xdi.oxd.common.params.RpAuthorizeRptParams;
//import org.xdi.oxd.common.params.RsCheckAccessParams;
//import org.xdi.oxd.common.params.RsProtectParams;
//import org.xdi.oxd.common.response.RegisterSiteResponse;
//import org.xdi.oxd.common.response.RsCheckAccessResponse;
//import org.xdi.oxd.rs.protect.Jackson;
//import org.xdi.oxd.rs.protect.RsResourceList;
//
//import com.google.common.collect.Lists;
//
////This class is resource provider or server class
//
//@RestController
//@CrossOrigin
//@RequestMapping("/")
//public class OxdProvider {
//
//	@Value("${rsProtect}")
//	private String rsProtect;
//
//	@Value("${oxd.host}")
//	private String oxdHost ;
//
//	@Value("${oxd.port}")
//	private int oxdPort;
//
//	@Value("${op.host}")
//	private String opHost ;
//
//	@Value("${oxd.token.file}")
//	private String oxdTokenContainer ;
//
//
//	/*
//	 * This method perform 3 Task
//	 * 1 - Registering the site
//	 * 2 - Protecting the resource
//	 * 3 - Writing generated oxd id in file for further use (needs to do some refracting for oxd token sharing)
//	 */
//
//	@GetMapping("/oxdId")
//	private ResponseEntity<?> oxdId(HttpServletRequest request) {
//		CommandClient client = null;
//
//		try {
//			client = new CommandClient(oxdHost, oxdPort);
//			RegisterSiteParams commandParams = new RegisterSiteParams();
//			commandParams.setOpHost(opHost);
//			commandParams.setAuthorizationRedirectUri("https://rks.local:9999/loginSuccess");
//			commandParams.setRedirectUris(Lists.newArrayList("https://rks.local:9999/logout"));
//			commandParams.setPostLogoutRedirectUri("https://rks.local:9999/logout");
//			commandParams.setClientLogoutUri(Lists.newArrayList("https://rks.local:9999/logout"));
//			commandParams.setAcrValues(Lists.newArrayList("auth_ldap_server"));
//			commandParams.setScope(Lists.newArrayList("openid","uma_protection", "uma_authorization"));
//			commandParams.setGrantType(Lists.newArrayList(GrantType.AUTHORIZATION_CODE.getValue()));
//			commandParams.setResponseTypes(Lists.newArrayList(ResponseType.CODE.getValue()));
//			//commandParams.setTrustedClient(true);
//			Command command = new Command(CommandType.REGISTER_SITE).setParamsObject(commandParams);
//			System.out.println(command.getParams());
//			RegisterSiteResponse site = client.send(command).dataAsResponse(RegisterSiteResponse.class);
//
//			protect(client, site.getOxdId());
//			request.getSession(true).setAttribute("oxdId", site.getOxdId());
//			writeOxdToken(site.getOxdId());
//
//			return new ResponseEntity<>("Resource is Protected", HttpStatus.OK);
//		} catch (IOException ioE) {
//
//			ioE.printStackTrace();
//			return new ResponseEntity<>("Error In Resource Protection", HttpStatus.INTERNAL_SERVER_ERROR);
//
//		} finally {
//			CommandClient.closeQuietly(client);
//		}
//	}
//
//	@GetMapping("/api/checkAccess")
//	public ResponseEntity<?> checkResourceAccess(@RequestParam("oxdId") String oxdId,@RequestParam("rpt") String rpt,
//			@RequestParam("path") String path,@RequestParam("httpMethod") String httpMethod) {
//
//		CommandClient client = null;
//		try{
//			client = new CommandClient(oxdHost, oxdPort);
//			RsCheckAccessResponse response = checkAccess(client, oxdId, "", path, httpMethod);
//			if(response != null ){
//				String ticket = response.getTicket();
//				authorizeRpt(client, oxdId, rpt, ticket);
//				response = checkAccess(client ,oxdId, rpt, path, httpMethod);
//				if(response.getAccess().equals("denied")){
//					return new ResponseEntity<>("Access to Resource Request is Denied.", HttpStatus.OK);
//				} else if(response.getAccess().equals("granted")){
//					return new ResponseEntity<>("Access to Resource Request is Granted.", HttpStatus.OK);
//				}
//			}
//			else {
//				return new ResponseEntity<>("Access to Resource Request is Denied.", HttpStatus.OK);
//			}
//		}
//		catch(IOException exception){
//			exception.printStackTrace();
//		}
//		finally{
//			CommandClient.closeQuietly(client);
//		}
//		return new ResponseEntity<>("Bad Request", HttpStatus.INTERNAL_SERVER_ERROR);
//	}
//
//	//Test resource(this resource will be protected)
//	@GetMapping("/api/resource")
//	private ResponseEntity<?> resource(HttpServletRequest request) {
//		HttpStatus status = HttpStatus.OK;
//		String message = "Test Resources";
//		return new ResponseEntity<>(message, status);
//	}
//
//	//protecting resource
//	public void protect(CommandClient client,String oxdId) throws IOException {
//		final RsProtectParams commandParams = new RsProtectParams();
//		commandParams.setOxdId(oxdId);
//		commandParams.setResources(resourceList().getResources());
//
//		final Command command = new Command(CommandType.RS_PROTECT)
//				.setParamsObject(commandParams);
//
//		client.send(command);
//	}
//
//	//checking access of a resource
//	public RsCheckAccessResponse checkAccess(CommandClient client,String oxdId,String rpt, String path, String httpMethod) {
//
//		RsCheckAccessParams params = new RsCheckAccessParams();
//		params.setOxdId(oxdId);
//		params.setPath(path);
//		params.setRpt(rpt);
//		params.setHttpMethod(httpMethod);
//		return client.send(new Command(CommandType.RS_CHECK_ACCESS, params)).dataAsResponse(RsCheckAccessResponse.class);
//
//	}
//
//	//authorizing rpt Token
//	public void authorizeRpt(CommandClient client,String oxdId, String rpt, String ticket) {
//
//		final RpAuthorizeRptParams params = new RpAuthorizeRptParams();
//		params.setOxdId(oxdId);
//		params.setRpt(rpt);
//		params.setTicket(ticket);
//		client.send(new Command(CommandType.RP_AUTHORIZE_RPT, params));
//
//	}
//
//	public void writeOxdToken(String oxdToken){
//		try{
//			FileWriter writer = new FileWriter(oxdTokenContainer);
//			writer.write(oxdToken);
//			writer.close();
//		}catch (Exception e) {
//			e.printStackTrace();
//		}
//	}
//
//	private RsResourceList resourceList() throws IOException {
//		rsProtect = StringUtils.replace(rsProtect, "'", "\"");
//		return Jackson.createJsonMapper().readValue(rsProtect, RsResourceList.class);
//	}
//
//}
