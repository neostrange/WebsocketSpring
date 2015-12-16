package com.tiss.tip.model;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Network Layer {@code Incident} where snort alert is triggered. Contains cid
 * for referring to the PCAP information in future.
 */
public class NetworkLayerIncident extends Incident {
	
	/**
	 * The logger for this class.
	 */
	private static Logger log = LoggerFactory.getLogger(NetworkLayerIncident.class);

	/**
	 * Id for referring to the full PCAP information from Snorby/Snort.
	 */
	private int cid;
	/**
	 * Id for referring to the sensor on which the attack was received.
	 */
	private int sid;
	/**
	 * Snort signature for this particular {@code Incident}.
	 */
	private String signature;
	/**
	 * Snort signature classification.
	 */
	private String signatureClass;
	/**
	 * If ICMP event, then the type of ICMP, eg. Echo is type 8.
	 */
	private String icmpType;

	
	/**
	 * Instantiates a new {@link NetworkLayerIncident}.
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
	 * @param origin
	 *            the origin {@link Origin}
	 * @param cid
	 *            the cid
	 * @param sid
	 *            the sid
	 * @param signature
	 *            the signature
	 * @param signatureClass
	 *            the signature class
	 * @param icmpType
	 *            the icmp type
	 */
	public NetworkLayerIncident(String dateTime, String srcIP, int srcPort, String service, String dstIP, int dstPort,
			String protocol, Origin org, int cid, int sid, String signature, String signatureClass, String icmpType) {
		super(dateTime, srcIP, srcPort, service, dstIP, dstPort, protocol, org);
		log.trace("Create new NetworkLayerIncident where cid [{}], sid [{}]", cid, sid);
		this.cid = cid;
		this.sid = sid;
		this.signature = signature;
		this.signatureClass = signatureClass;
		this.icmpType = icmpType;
	}

	/**
	 * Instantiates a new network layer incident.
	 *
	 * @param dateTime
	 *            the date time
	 * @param srcIP
	 *            the src ip
	 * @param srcPort
	 *            the src port
	 * @param service
	 *            the service
	 * @param dstIP
	 *            the dst ip
	 * @param dstPort
	 *            the dst port
	 * @param protocol
	 *            the protocol
	 * @param org
	 *            the org
	 * @param cid
	 *            the cid
	 * @param sid
	 *            the sid
	 * @param signature
	 *            the signature
	 * @param signatureClass
	 *            the signature class
	 */
	// Without ICMP type
	public NetworkLayerIncident(String dateTime, String srcIP, int srcPort, String service, String dstIP, int dstPort,
			String protocol, Origin org, int cid, int sid, String signature, String signatureClass) {
		super(dateTime, srcIP, srcPort, service, dstIP, dstPort, protocol, org);
		log.trace("Create new NetworkLayerIncident where cid [{}], sid [{}]", cid, sid);
		this.cid = cid;
		this.sid = sid;
		this.signature = signature;
		this.signatureClass = signatureClass;
		this.icmpType = null;
	}

	/**
	 * Gets the id for referring to the full PCAP information from Snorby/Snort.
	 *
	 * @return the id for referring to the full PCAP information from
	 *         Snorby/Snort
	 */
	public int getCid() {
		log.trace("Get cid, returns [{}]", cid);
		return cid;
	}

	/**
	 * Sets the id for referring to the full PCAP information from Snorby/Snort.
	 *
	 * @param cid
	 *            the new id for referring to the full PCAP information from
	 *            Snorby/Snort
	 */
	public void setCid(int cid) {
		log.trace("Set cid to [{}]", cid);
		this.cid = cid;
	}

	/**
	 * Gets the id for referring to the sensor on which the attack was received.
	 *
	 * @return the id for referring to the sensor on which the attack was
	 *         received
	 */
	public int getSid() {
		log.trace("Get sid, returns [{}]", sid);
		return sid;
	}

	/**
	 * Sets the id for referring to the sensor on which the attack was received.
	 *
	 * @param sid
	 *            the new id for referring to the sensor on which the attack was
	 *            received
	 */
	public void setSid(int sid) {
		log.trace("Set sid to [{}]", sid);
		this.sid = sid;
	}

	/**
	 * Gets the snort signature for this particular {@code Incident}.
	 *
	 * @return the snort signature for this particular {@code Incident}
	 */
	public String getSignature() {
		log.trace("Get signature, returns [{}]", signature);
		return signature;
	}

	/**
	 * Sets the snort signature for this particular {@code Incident}.
	 *
	 * @param signature
	 *            the new snort signature for this particular {@code Incident}
	 */
	public void setSignature(String signature) {
		log.trace("Set signature to [{}]", signature);
		this.signature = signature;
	}

	/**
	 * Gets the snort signature classification.
	 *
	 * @return the snort signature classification
	 */
	public String getSignatureClass() {
		log.trace("Get signatureClass, returns [{}]", signatureClass);
		return signatureClass;
	}

	/**
	 * Sets the snort signature classification.
	 *
	 * @param signature_class
	 *            the new snort signature classification
	 */
	public void setSignatureClass(String signature_class) {
		log.trace("Set signatureClass to [{}]", signature_class);
		this.signatureClass = signature_class;
	}

	/**
	 * Gets the type of ICMP, eg. Echo is type 8.
	 *
	 * @return the if ICMP event, then the type of ICMP, eg
	 */
	public String getIcmpType() {
		log.trace("Get icmpType, returns [{}]", icmpType);
		return icmpType;
	}

	/**
	 * Sets the type of ICMP, eg. Echo is type 8.
	 *
	 * @param icmpType
	 *            the new if ICMP event, then the type of ICMP, eg
	 */
	public void setIcmpType(String icmpType) {
		log.trace("Set icmpType to [{}]", icmpType);
		this.icmpType = icmpType;
	}

}