/*
*  Copyright © 2015  WSO2.Telco. All rights reserved.
*  Author :Nuwan Walisundara
*  Date : Dec 11, 2015

*/
package org.wso2telco.carbon.security.valve;

import java.io.IOException;

import javax.servlet.ServletException;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.wso2.carbon.base.ServerConfiguration;

public class CSRFValve extends ValveBase{
	/*  31 */   private static String REFERER_HEADER = "referer";
	/*  32 */   private static String CSRF_VALVE_PROPERTY = "Security.CSRFPreventionConfig";
	/*  33 */   private static String ENABLED_PROPERTY = CSRF_VALVE_PROPERTY + ".Enabled";
	/*  34 */   private static String WHITE_LIST_PROPERTY = CSRF_VALVE_PROPERTY + ".WhiteList.Url";
	/*  35 */   private static String RULE_PATTERN_PROPERTY = CSRF_VALVE_PROPERTY + ".Patterns.Pattern";
	/*  36 */   private static String RULE_PROPERTY = CSRF_VALVE_PROPERTY + ".Rule";
	/*  37 */   private static String RULE_ALLOW = "allow";
	/*  38 */   private static String RULE_DENY = "deny";
	/*     */   private static String[] csrfPatternList;
	/*     */   private static String[] whiteList;
	/*     */   private static String csrfRule;
	/*  42 */   private static boolean csrfEnabled = false;
	/*     */   
	/*     */ 
	/*     */ 
	/*     */ 
	/*     */   private void loadConfiguration()
	/*     */   {
	/*  49 */     ServerConfiguration serverConfiguration = ServerConfiguration.getInstance();
	/*  50 */     whiteList = serverConfiguration.getProperties(WHITE_LIST_PROPERTY);
	/*  51 */     csrfPatternList = serverConfiguration.getProperties(RULE_PATTERN_PROPERTY);
	/*  52 */     csrfRule = serverConfiguration.getFirstProperty(RULE_PROPERTY);
	/*  53 */     if ((whiteList.length > 0) && (csrfPatternList.length > 0) && (csrfRule != null) && (serverConfiguration.getFirstProperty(ENABLED_PROPERTY) != null) && (Boolean.parseBoolean(serverConfiguration.getFirstProperty(ENABLED_PROPERTY))))
	/*     */     {
	/*     */ 
	/*  56 */       csrfEnabled = true;
	/*     */     }
	/*     */   }
	/*     */   
	/*     */   protected void initInternal() throws LifecycleException
	/*     */   {
	/*  62 */     super.initInternal();
	/*  63 */     loadConfiguration();
	/*     */   }
	/*     */   
	/*     */   public void invoke(Request request, Response response)
	/*     */     throws IOException, ServletException
	/*     */   {
	/*  69 */     if (csrfEnabled) {
	/*  70 */       validatePatterns(request);
	/*     */     }
	/*  72 */     getNext().invoke(request, response);
	/*     */   }
	/*     */   
	/*     */ 
	/*     */ 
	/*     */ 
	/*     */ 
	/*     */ 
	/*     */ 
	/*     */   private void validatePatterns(Request request)
	/*     */     throws ServletException
	/*     */   {
	/*  84 */     String context = request.getRequestURI().substring(request.getRequestURI().indexOf("/") + 1);
	/*     */     
	/*  86 */     if ((RULE_ALLOW.equals(csrfRule)) && (!isContextStartWithGivenPatterns(context))) {
	/*  87 */       validateRefererHeader(request);
	/*  88 */     } else if ((RULE_DENY.equals(csrfRule)) && (isContextStartWithGivenPatterns(context))) {
	/*  89 */       validateRefererHeader(request);
	/*     */     }
	/*     */   }
	/*     */   
	/*     */ 
	/*     */ 
	/*     */ 
	/*     */ 
	/*     */ 
	/*     */ 
	/*     */   private boolean isContextStartWithGivenPatterns(String context)
	/*     */   {
	/* 101 */     boolean patternMatched = false;
	/*     */     
	/* 103 */     for (String pattern : csrfPatternList) {
	/* 104 */       if (context.startsWith(pattern)) {
	/* 105 */         patternMatched = true;
	/* 106 */         break;
	/*     */       }
	/*     */     }
	/* 109 */     return patternMatched;
	/*     */   }
	/*     */   
	/*     */ 
	/*     */ 
	/*     */ 
	/*     */ 
	private void validateRefererHeader(Request request)  throws ServletException
	   {
	     String refererHeader = request.getHeader(REFERER_HEADER);
	     
	     boolean allow = false;
	     if (refererHeader != null) {
	       for (String ip : whiteList) {
	         if (refererHeader.startsWith(ip)) {
	           allow = true;
	           break;
	         }
	       }
	       if (!allow) {
	         throw new ServletException("Possible CSRF attack. Refer header : " + refererHeader);
	       }
	     }else{
	    	 throw new ServletException("Possible CSRF attack. missing Refer header " );
	     }
	   }
	}
