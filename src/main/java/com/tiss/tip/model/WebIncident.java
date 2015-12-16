package com.tiss.tip.model;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO: Auto-generated Javadoc
/**
 * This class represents an {@code Incident} on the Application Layer.
 */
public class WebIncident extends Incident {

	/**
	 * The logger for this class.
	 */
	private static Logger log = LoggerFactory.getLogger(WebIncident.class);

	/**
	 * Length of content in request.
	 */
	private int contentLength;
	/**
	 * Type of MIME content in request.
	 */
	private String contentType;
	/**
	 * HTTP method used in request, eg. GET, POST, etc.
	 */
	private String httpMethod;
	/**
	 * Path requested by attacker.
	 */
	private String pathParameter;
	/**
	 * If request is referred by an intermediary.
	 */
	private String referer;
	/**
	 * List of Modsecurity rules triggered.
	 */
	private List<WebRule> rulesList;
	/**
	 * Severity Id of the {@code Incident}.
	 */
	private int severityId;
	/**
	 * Severity status of the {@code Incident}.
	 */
	private String severityStatus;
	/**
	 * The user agent or tool used by the attacker.
	 */
	private String userAgent;

	/**
	 * Instantiates a new web incident.
	 *
		 * @param dateTime
	 *            the date time
	 * @param srcIP
	 *            the source IP
	 * @param srcPort
	 *            the source port
	 * @param service
	 *            the service
	 * @param dstIP
	 *            the destination ip
	 * @param dstPort
	 *            the destination port
	 * @param protocol
	 *            the protocol
	 * @param org
	 *            the origin {@link Origin}
	 * @param contentLength
	 *            the content length
	 * @param contentType
	 *            the content type
	 * @param httpMethod
	 *            the http method
	 * @param pathParameter
	 *            the path parameter
	 * @param referer
	 *            the referer
	 * @param rulesList
	 *            the rules list {@link WebRule}
	 * @param severityId
	 *            the severity id
	 * @param severityStatus
	 *            the severity status
	 * @param userAgent
	 *            the user agent
	 */
	public WebIncident(String dateTime, String srcIP, int srcPort, String service, String dstIP, int dstPort,
			String protocol, Origin org, int contentLength, String contentType, String httpMethod, String pathParameter,
			String referer, List<WebRule> rulesList, int severityId, String severityStatus, String userAgent) {
		super(dateTime, srcIP, srcPort, service, dstIP, dstPort, protocol, org);
		log.trace("Create new WebIncident where contentLength [{}], contentType [{}]", contentLength, contentType);
		this.contentLength = contentLength;
		this.contentType = contentType;
		this.httpMethod = httpMethod;
		this.pathParameter = pathParameter;
		this.referer = referer;
		this.rulesList = rulesList;
		this.severityId = severityId;
		this.severityStatus = severityStatus;
		this.userAgent = userAgent;
	}

	/**
	 * Gets the length of content in request.
	 *
	 * @return the length of content in request
	 */
	public int getContentLength() {
		log.trace("Get contentLength, returns [{}]", contentLength);
		return contentLength;
	}

	/**
	 * Sets the length of content in request.
	 *
	 * @param contentLength
	 *            the new length of content in request
	 */
	public void setContentLength(int contentLength) {
		log.trace("Set contentLength to [{}]", contentLength);
		this.contentLength = contentLength;
	}

	/**
	 * Gets the type of MIME content in request.
	 *
	 * @return the type of MIME content in request
	 */
	public String getContentType() {
		log.trace("Get contentType, returns [{}]", contentType);
		return contentType;
	}

	/**
	 * Sets the type of MIME content in request.
	 *
	 * @param contentType
	 *            the new type of MIME content in request
	 */
	public void setContentType(String contentType) {
		log.trace("Set contentType to [{}]", contentType);
		this.contentType = contentType;
	}

	/**
	 * Gets the hTTP method used in request, eg. GET, POST, etc.
	 *
	 * @return the hTTP method used in request, eg
	 */
	public String getHttpMethod() {
		log.trace("Get httpMethod, returns [{}]", httpMethod);
		return httpMethod;
	}

	/**
	 * Sets the hTTP method used in request, eg. GET, POST, etc.
	 *
	 * @param httpMethod
	 *            the new hTTP method used in request, eg
	 */
	public void setHttpMethod(String httpMethod) {
		log.trace("Set httpMethod to [{}]", httpMethod);
		this.httpMethod = httpMethod;
	}

	/**
	 * Gets the path requested by attacker.
	 *
	 * @return the path requested by attacker
	 */
	public String getPathParameter() {
		log.trace("Get pathParameter, returns [{}]", pathParameter);
		return pathParameter;
	}

	/**
	 * Sets the path requested by attacker.
	 *
	 * @param pathParameter
	 *            the new path requested by attacker
	 */
	public void setPathParameter(String pathParameter) {
		log.trace("Set pathParameter to [{}]", pathParameter);
		this.pathParameter = pathParameter;
	}

	/**
	 * Gets the if request is referred by an intermediary.
	 *
	 * @return the if request is referred by an intermediary
	 */
	public String getReferer() {
		log.trace("Get referer, returns [{}]", referer);
		return referer;
	}

	/**
	 * Sets the if request is referred by an intermediary.
	 *
	 * @param referer
	 *            the new if request is referred by an intermediary
	 */
	public void setReferer(String referer) {
		log.trace("Set referer to [{}]", referer);
		this.referer = referer;
	}

	/**
	 * Gets the list of Modsecurity rules triggered.
	 *
	 * @return the list of {@link WebRule}, Modsecurity rules triggered
	 */
	public List<WebRule> getRulesList() {
		log.trace("Get rulesList, returns [{}]", rulesList);
		return rulesList;
	}

	/**
	 * Sets the list of Modsecurity rules triggered.
	 *
	 * @param rulesList
	 *            the new list of {@link WebRule}, Modsecurity rules triggered
	 */
	public void setRulesList(List<WebRule> rulesList) {
		log.trace("Set rulesList to [{}]", rulesList);
		this.rulesList = rulesList;
	}

	/**
	 * Gets the severity Id of the {@code Incident}.
	 *
	 * @return the severity Id of the {@code Incident}
	 */
	public int getSeverityId() {
		log.trace("Get severityId, returns [{}]", severityId);
		return severityId;
	}

	/**
	 * Sets the severity Id of the {@code Incident}.
	 *
	 * @param severityId
	 *            the new severity Id of the {@code Incident}
	 */
	public void setSeverityId(int severityId) {
		log.trace("Set severityId to [{}]", severityId);
		this.severityId = severityId;
	}

	/**
	 * Gets the severity status of the {@code Incident}.
	 *
	 * @return the severity status of the {@code Incident}
	 */
	public String getSeverityStatus() {
		log.trace("Get severityStatus, returns [{}]", severityStatus);
		return severityStatus;
	}

	/**
	 * Sets the severity status of the {@code Incident}.
	 *
	 * @param severityStatus
	 *            the new severity status of the {@code Incident}
	 */
	public void setSeverityStatus(String severityStatus) {
		log.trace("Set severityStatus to [{}]", severityStatus);
		this.severityStatus = severityStatus;
	}

	/**
	 * Gets the user agent or tool used by the attacker.
	 *
	 * @return the user agent or tool used by the attacker
	 */
	public String getUserAgent() {
		log.trace("Get userAgent, returns [{}]", userAgent);
		return userAgent;
	}

	/**
	 * Sets the user agent or tool used by the attacker.
	 *
	 * @param userAgent
	 *            the new user agent or tool used by the attacker
	 */
	public void setUserAgent(String userAgent) {
		log.trace("Set userAgent to [{}]", userAgent);
		this.userAgent = userAgent;
	}

}