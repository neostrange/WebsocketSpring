package com.tiss.tip.model;

import java.io.Serializable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;

/**
 * This is the main incident class which contains all the common elements found
 * in all its subtypes.
 */

public class Incident implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = -5116337303715171924L;

	/** The logger for this class. */
	private static Logger log = LoggerFactory.getLogger(Incident.class);

	/**
	 * The incident datetime.
	 */
	private String dateTime;
	/**
	 * IP of the source that the attack originated from.
	 */
	private String srcIP;
	/**
	 * Source port where the attack originated from.
	 */
	private int srcPort;
	/**
	 * The type of service.
	 */
	private String service;
	/**
	 * This is the destination IP address of the targeted sensor.
	 */
	private String dstIP;
	/**
	 * This is the destination port of the targeted sensor.
	 */
	private int dstPort;
	/**
	 * The transport layer protocol (tcp, udp, etc).
	 */
	private String protocol;
	/**
	 * The information regarding the origin of the attack.
	 */
	@Field (type = FieldType.Object)
	private Origin origin;
	
	
	public Incident(){}

	/**
	 * Instantiates a new {@link Incident}.
	 *
	 * @param dateTime the date time
	 * @param srcIP the source IP
	 * @param srcPort the source port
	 * @param service the service
	 * @param dstIP the destination IP
	 * @param dstPort the destination port
	 * @param protocol the protocol
	 * @param org the origin {@link Origin}
	 */
	public Incident(String dateTime, String srcIP, int srcPort, String service, String dstIP, int dstPort,
			String protocol, Origin org) {
		log.trace("Create new Incident instance with dateTime [{}], srcIP [{}], dstIP [{}], dstPort [{}] ", dateTime,
				srcIP, dstIP, dstPort);
		this.dateTime = dateTime;
		this.srcIP = srcIP;
		this.srcPort = srcPort;
		this.service = service;
		this.dstIP = dstIP;
		this.dstPort = dstPort;
		this.protocol = protocol;
		this.origin = org;
	}

	/**
	 * Gets the date time.
	 *
	 * @return the date time
	 */
	public String getDateTime() {
		log.trace("Get dateTime, returns [{}]", dateTime);
		return dateTime;
	}

	/**
	 * Sets the date time.
	 *
	 * @param datetime the new date time
	 */
	public void setDateTime(String datetime) {
		log.trace("Set dateTime to [{}]", datetime);
		this.dateTime = datetime;
	}

	/**
	 * Gets the src ip.
	 *
	 * @return the src ip
	 */
	public String getSrcIP() {
		log.trace("Get srcIP, returns [{}]", srcIP);
		return srcIP;
	}

	/**
	 * Sets the src ip.
	 *
	 * @param srcIP the new src ip
	 */
	public void setSrcIP(String srcIP) {
		log.trace("Set srcIP to [{}]", srcIP);
		this.srcIP = srcIP;
	}

	/**
	 * Gets the src port.
	 *
	 * @return the src port
	 */
	public int getSrcPort() {
		log.trace("Get srcPort, returns [{}]", srcPort);
		return srcPort;
	}

	/**
	 * Sets the source port.
	 *
	 * @param srcPort the new source port
	 */
	public void setSourcePort(int srcPort) {
		log.trace("Set SourcePort to [{}]", srcPort);
		this.srcPort = srcPort;
	}

	/**
	 * Gets the service.
	 *
	 * @return the service
	 */
	public String getService() {
		return service;
	}

	/**
	 * Sets the service.
	 *
	 * @param service the new service
	 */
	public void setService(String service) {
		log.trace("Set Service to [{}]", service);
		this.service = service;
	}

	/**
	 * Gets the dst ip.
	 *
	 * @return the dst ip
	 */
	public String getDstIP() {
		log.trace("Get dstIP, returns [{}]", dstIP);
		return dstIP;
	}

	/**
	 * Sets the destination ip.
	 *
	 * @param dstIP the new destination ip
	 */
	public void setDestinationIP(String dstIP) {
		log.trace("Set DestinationIP to [{}]", dstIP);
		this.dstIP = dstIP;
	}

	/**
	 * Gets the dst port.
	 *
	 * @return the dst port
	 */
	public int getDstPort() {
		log.trace("Get dstPort, returns [{}]", dstPort);
		return dstPort;
	}

	/**
	 * Sets the dst port.
	 *
	 * @param dstPort the new dst port
	 */
	public void setDstPort(int dstPort) {
		log.trace("Set dstPort to [{}]", dstPort);
		this.dstPort = dstPort;
	}

	/**
	 * Gets the protocol.
	 *
	 * @return the protocol
	 */
	public String getProtocol() {
		log.trace("Get protocol, returns [{}]", protocol);
		return protocol;
	}

	/**
	 * Sets the protocol.
	 *
	 * @param protocol the new protocol
	 */
	public void setProtocol(String protocol) {
		log.trace("Set protocol to [{}]", protocol);
		this.protocol = protocol;
	}

	/**
	 * Gets the origin.
	 *
	 * @return the origin
	 */
	public Origin getOrigin() {
		log.trace("Get origin, returns [{}]", origin);
		return origin;
	}

	/**
	 * Sets the origin.
	 *
	 * @param org the new origin
	 */
	public void setOrigin(Origin org) {
		log.trace("Set origin to [{}]", org);
		this.origin = org;
	}

}