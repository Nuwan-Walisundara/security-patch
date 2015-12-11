/*
*  Copyright © 2015  WSO2.Telco. All rights reserved.
*  Author :Nuwan Walisundara
*  Date : Dec 11, 2015

*/
package org.wso2telco.carbon.security.valve;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.utils.CarbonUtils;

public class XSSValve extends ValveBase {
	private static String XSS_VALVE_PROPERTY = "Security.XSSPreventionConfig";
	private static String ENABLED_PROPERTY = XSS_VALVE_PROPERTY + ".Enabled";
	private static String RULE_PATTERN_PROPERTY = XSS_VALVE_PROPERTY + ".Patterns.Pattern";
	private static String RULE_PROPERTY = XSS_VALVE_PROPERTY + ".Rule";
	private static String XSS_EXTENSION_FILE_NAME = "xss-patterns.properties";
	private static boolean xssEnabled = false;
	/* 50 */ private static String RULE_ALLOW = "allow";
	/* 51 */ private static String RULE_DENY = "deny";
	/*     */ private static String[] xssURIPatternList;
	/*     */ private static String xssRule;
	/* 54 */ private static String patterPath = "";
	/*     */
	/*     */ private static ArrayList<Pattern> patternList;
	/* 57 */ protected static final Log log = LogFactory.getLog(XSSValve.class);
	/*     */
	/*     */
	/* 60 */ private static Pattern[] patterns = { Pattern.compile("<isindex", Pattern.CASE_INSENSITIVE),
													Pattern.compile("<input", Pattern.CASE_INSENSITIVE), 
													Pattern.compile("<body", Pattern.CASE_INSENSITIVE),
													Pattern.compile("<link", Pattern.CASE_INSENSITIVE),
													Pattern.compile("<link", Pattern.CASE_INSENSITIVE),
													Pattern.compile("<script>(.*?)</script>",Pattern.CASE_INSENSITIVE),
													Pattern.compile("src[\r\n]*=[\r\n]*\\'(.*?)\\'", 42),
													Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", 42), 
													Pattern.compile("</script>", Pattern.CASE_INSENSITIVE),
													Pattern.compile("<script(.*?)>", 42), 
													Pattern.compile("eval\\((.*?)\\)", 42),
													Pattern.compile("expression\\((.*?)\\)", 42), 
													Pattern.compile("<img", Pattern.CASE_INSENSITIVE), 
													Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
													Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE), 
													Pattern.compile("alert(.*)",Pattern.CASE_INSENSITIVE),
													Pattern.compile("onMouse", Pattern.CASE_INSENSITIVE),
													Pattern.compile("onload(.*?)=", 42) };

	/*     */ protected void initInternal()/*     */ throws LifecycleException
	/*     */ {
		/* 84 */ super.initInternal();
		/* 85 */ loadConfiguration();
		/*     */ }

	/*     */
	/*     */
	/*     */
	/*     */
	/*     */ private void loadConfiguration()
	/*     */ {
		/* 93 */ ServerConfiguration serverConfiguration = ServerConfiguration.getInstance();
		/* 94 */ if ((serverConfiguration.getFirstProperty(ENABLED_PROPERTY) != null)
				&& (Boolean.parseBoolean(serverConfiguration.getFirstProperty(ENABLED_PROPERTY))))
		/*     */ {
			/* 96 */ xssEnabled = true;
			/*     */ }
		/* 98 */ xssURIPatternList = serverConfiguration.getProperties(RULE_PATTERN_PROPERTY);
		/* 99 */ xssRule = serverConfiguration.getFirstProperty(RULE_PROPERTY);
		/* 100 */ patterPath = CarbonUtils.getCarbonSecurityConfigDirPath() + "/" + XSS_EXTENSION_FILE_NAME;
		/* 101 */ buildScriptPatterns();
		/*     */ }

	/*     */
	/*     */ public void invoke(Request request, Response response)/*     */ throws IOException, ServletException
	/*     */ {
		/* 107 */ if (xssEnabled) {
			/* 108 */ String context = request.getRequestURI().substring(request.getRequestURI().indexOf("/") + 1);
			/* 109 */ if ((RULE_ALLOW.equals(xssRule)) && (!isContextStartWithGivenPatterns(context))) {
				/* 110 */ validateParameters(request);
				/* 111 */ } else if ((RULE_DENY.equals(xssRule)) && (isContextStartWithGivenPatterns(context))) {
				/* 112 */ validateParameters(request);
				/* 113 */ } else if ((!RULE_ALLOW.equals(xssRule)) && (!RULE_DENY.equals(xssRule))) {
				/* 114 */ validateParameters(request);
				/*     */ }
			/*     */ }
		/*     */
		/* 118 */ getNext().invoke(request, response);
		/*     */ }

	/*     */
	/*     */ private void validateParameters(Request request) throws ServletException
	/*     */ {
		/* 123 */ Enumeration<String> parameterNames = request.getParameterNames();
		/*     */ String paramValue;
		/* 125 */ while (parameterNames.hasMoreElements())
		/*     */ {
			/* 127 */ String paramName = (String) parameterNames.nextElement();
			/* 128 */ paramValue = request.getParameter(paramName);
			/* 129 */ if (paramValue != null) {
				/* 130 */ paramValue = paramValue.replaceAll("\000", "");
				/* 131 */ for (Pattern scriptPattern : patternList) {
					/* 132 */ Matcher matcher = scriptPattern.matcher(paramValue);
					/* 133 */ if (matcher.find()) {
						/* 134 */ throw new ServletException(
								"Possible XSS Attack. Suspicious code : " + matcher.toMatchResult().group());
						/*     */ }
					/*     */ }
				/*     */ }
			/*     */ }
		/*     */ }

	/*     */
	/*     */
	/*     */
	/*     */
	/*     */
	/*     */
	/*     */
	/*     */
	/*     */ private boolean isContextStartWithGivenPatterns(String context)
	/*     */ {
		/* 150 */ boolean patternMatched = false;
		/*     */
		/* 152 */ for (String pattern : xssURIPatternList) {
			/* 153 */ if (context.startsWith(pattern)) {
				/* 154 */ patternMatched = true;
				/* 155 */ break;
				/*     */ }
			/*     */ }
		/* 158 */ return patternMatched;
		/*     */ }

	/*     */
	/*     */ private void buildScriptPatterns() {
		/* 162 */ patternList = new ArrayList(Arrays.asList(patterns));
		/* 163 */ Properties properties;
		if ((patterPath != null) && (!patterPath.isEmpty())) {
			/* 164 */ InputStream inStream = null;
			/* 165 */ File xssPatternConfigFile = new File(patterPath);
			/* 166 */ properties = new Properties();
			/* 167 */ if (xssPatternConfigFile.exists()) {
				/*     */ try {
					/* 169 */ inStream = new FileInputStream(xssPatternConfigFile);
					/* 170 */ properties.load(inStream);
					/*     */
					/*     */
					/*     */
					/*     */
					/*     */
					/* 176 */ if (inStream != null) {
						/*     */ try {
							/* 178 */ inStream.close();
							/*     */ } catch (IOException e) {
							/* 180 */ log.error("Error while closing stream ", e);
							/*     */ }
						/*     */ }
					/*     */
					/*     */
					/* 185 */ if (properties.isEmpty()) {
						/*     */ return;
						/*     */ }
					/*     */ }
					/*     */ catch (FileNotFoundException e)
				/*     */ {
					/* 172 */ log.error("Can not load xssPatternConfig properties file ", e);
					/*     */ } catch (IOException e) {
					/* 174 */ log.error("Can not load xssPatternConfigFile properties file ", e);
					/*     */ } finally {
					/* 176 */ if (inStream != null) {
						/*     */ try {
							/* 178 */ inStream.close();
							/*     */ } catch (IOException e) {
							/* 180 */ log.error("Error while closing stream ", e);
							/*     */ }
						/*     */ }
					/*     */ }
				/*     */ }
			/*     */
			/* 186 */ for (String key : properties.stringPropertyNames()) {
				/* 187 */ String value = properties.getProperty(key);
				/* 188 */ patternList.add(Pattern.compile(value, 2));
				/*     */ }
			/*     */ }
		/*     */ }
	/*     */ }
