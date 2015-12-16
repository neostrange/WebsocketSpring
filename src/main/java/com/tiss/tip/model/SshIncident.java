package com.tiss.tip.model;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO: Auto-generated Javadoc
/**
 * This class represents an SSH {@code Incident}.
 */
public class SshIncident extends Incident {
	
	/**
	 * The logger for this class.
	 */
	private static Logger log = LoggerFactory.getLogger(SshIncident.class);

	/** For referring to MalwareIncidents. */
	private String sessionId;

	/**
	 * The list of Authentication attempts made by the attacker.
	 */
	private List<Auth> authList;
	/**
	 * The time attacker's SSH session ended.
	 */
	private String endTime;
	/**
	 * The list of commands the attacker attempted to execute.
	 */
	private List<Input> inputList;
	/**
	 * The SSH tool used by the attacker.
	 */
	private String tool;

	/**
	 * Instantiates a new {@link SshIncident}.
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
	 * @param sessionId
	 *            the session id
	 * @param authList
	 *            the auth list
	 * @param endtime
	 *            the endtime
	 * @param inputList
	 *            the input list
	 * @param tool
	 *            the SSH tool
	 */
	public SshIncident(String dateTime, String srcIP, int srcPort, String service, String dstIP, int dstPort,
			String protocol, Origin org, String sessionId, List<Auth> authList, String endtime, List<Input> inputList,
			String tool) {
		super(dateTime, srcIP, srcPort, service, dstIP, dstPort, protocol, org);
		log.trace("Create new SshIncident where sessionId [{}]", sessionId);
		this.sessionId = sessionId;
		this.authList = authList;
		this.endTime = endtime;
		this.inputList = inputList;
		this.tool = tool;
	}

	/**
	 * Gets the for referring to MalwareIncidents.
	 *
	 * @return the for referring to MalwareIncidents
	 */
	public String getSessionId() {
		log.trace("Get sessionId, returns [{}]", sessionId);
		return sessionId;
	}

	/**
	 * Sets the for referring to MalwareIncidents.
	 *
	 * @param sessionId
	 *            the new for referring to MalwareIncidents
	 */
	public void setSessionId(String sessionId) {
		log.trace("Set sessionId to [{}]", sessionId);
		this.sessionId = sessionId;
	}

	/**
	 * Gets the list of Authentication attempts made by the attacker.
	 *
	 * @return the list of {@link Auth} attempts made by the attacker
	 */
	public List<Auth> getAuthList() {
		log.trace("Get authList, returns [{}]", authList);
		return authList;
	}

	/**
	 * Sets the list of Authentication attempts made by the attacker.
	 *
	 * @param authList
	 *            the new list of {@link Auth} attempts made by the attacker
	 */
	public void setAuthList(List<Auth> authList) {
		log.trace("Set authList to [{}]", authList);
		this.authList = authList;
	}

	/**
	 * Gets the time attacker's SSH session ended.
	 *
	 * @return the time attacker's SSH session ended
	 */
	public String getEndTime() {
		log.trace("Get endTime, returns [{}]", endTime);
		return endTime;
	}

	/**
	 * Sets the time attacker's SSH session ended.
	 *
	 * @param endtime
	 *            the new time attacker's SSH session ended
	 */
	public void setEndTime(String endtime) {
		log.trace("Set endTime to [{}]", endtime);
		this.endTime = endtime;
	}

	/**
	 * Gets the list of commands the attacker attempted to execute.
	 *
	 * @return the list of {@link Input} commands the attacker attempted to execute
	 */
	public List<Input> getInputList() {
		log.trace("Get InputList, returns [{}]", inputList);
		return inputList;
	}

	/**
	 * Sets the list of commands the attacker attempted to execute.
	 *
	 * @param inputList
	 *            the new list of {@link Input} commands the attacker attempted to execute
	 */
	public void setInputList(List<Input> inputList) {
		log.trace("Set inputList to [{}]", inputList);
		this.inputList = inputList;
	}

	/**
	 * Gets the SSH tool used by the attacker.
	 *
	 * @return the SSH tool used by the attacker
	 */
	public String getTool() {
		log.trace("Get tool, returns [{}]", tool);
		return tool;
	}

	/**
	 * Sets the SSH tool used by the attacker.
	 *
	 * @param tool
	 *            the new SSH tool used by the attacker
	 */
	public void setTool(String tool) {
		log.trace("Set tool to [{}]", tool);
		this.tool = tool;
	}

}