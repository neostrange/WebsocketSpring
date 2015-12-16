package com.tiss.tip.model;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class contains the virustotal scan reference and individual scanner
 * results.
 */
public class VirusTotalScan {

	/**
	 * The logger for this class.
	 */
	private static Logger log = LoggerFactory.getLogger(VirusTotalScan.class);

	/**
	 * The URL for the full virustotal analysis result.
	 */
	private String permalink;
	/**
	 * HashMap scanner result of analysis, where key is scanner and value is its
	 * result.
	 */
	private HashMap<String, String> VTscanResults;

	public VirusTotalScan() {
		super();
	}

	/**
	 * Instantiates a new virus total scan.
	 *
	 * @param permalink
	 *            the permalink for Virustotal scan
	 * @param vTscanResults
	 *            {@code HashMap} of the vtscan results
	 */
	public VirusTotalScan(String permalink, HashMap<String, String> vTscanResults) {
		super();
		log.trace("Create new VirusTotalScan instance with permalink [{}]", permalink);
		this.permalink = permalink;
		VTscanResults = vTscanResults;
	}

	/**
	 * Gets the URL for the full virustotal analysis result.
	 *
	 * @return the URL for the full virustotal analysis result
	 */
	public String getPermalink() {
		log.trace("Get permalink, returns [{}]", permalink);
		return permalink;
	}

	/**
	 * Sets the URL for the full virustotal analysis result.
	 *
	 * @param permalink
	 *            the new URL for the full virustotal analysis result
	 */
	public void setPermalink(String permalink) {
		log.trace("Set permalink to [{}]", permalink);
		this.permalink = permalink;
	}

	/**
	 * Gets the virustotal scan results.
	 *
	 * @return the {@code HashMap} of virustotal scan results
	 */
	public HashMap<String, String> getVTscanResults() {
		log.trace("Get VTscanResults, returns [{}]", VTscanResults);
		return VTscanResults;
	}

	/**
	 * Sets the virustotal scan results.
	 *
	 * @param vTscanResultList
	 *            the {@code HashMap} of virustotal scan results
	 */
	public void setVTscanResults(HashMap<String, String> vTscanResultList) {
		log.trace("Set VTscanResults to [{}]", VTscanResults);
		VTscanResults = vTscanResultList;
	}

}