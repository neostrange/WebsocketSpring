package com.tiss.tip.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.dal.GlobalThreatQueryCreator;

@Service
public class GlobalThreatService {

	@Autowired
	private GlobalThreatQueryCreator globalService;

	public List<JsonNode> getGlobalAttackSummary(String from, String to, String countryCode) {
		return globalService.getGlobalAttacks(from, to, countryCode);
	}

	public List<JsonNode> getAttackSummary(String from, String to, String countryCode, String attackType) {
		switch (attackType) {
		case "ssh":
			return globalService.getGlobalSSH(from, to, countryCode);
		case "malware":
			return globalService.getGlobalMalware(from, to, countryCode);
		case "db":
			return globalService.getGlobalDatabase(from, to, countryCode);
		case "sip":
			return globalService.getGlobalSip(from, to, countryCode);
		case "application":
			return globalService.getGlobalApplication(from, to, countryCode);
		case "web":
			return globalService.getGlobalWeb(from, to, countryCode);
		default:
			// logger.err //TODO

		}
		return null;

	}

	public List<JsonNode> getSshAttackSummary(String from, String to, String countryCode) {
		return globalService.getGlobalSSH(from, to, countryCode);
	}

	public List<JsonNode> getMalwareAttackSummary(String from, String to, String countryCode) {
		return globalService.getGlobalMalware(from, to, countryCode);
	}

	public List<JsonNode> getDbSummary(String from, String to, String countryCode) {
		return globalService.getGlobalDatabase(from, to, countryCode);
	}

	public List<JsonNode> getSipAttackSummary(String from, String to, String countryCode) {
		return globalService.getGlobalSip(from, to, countryCode);
	}

	public List<JsonNode> getApplicationExpAttackSummary(String from, String to, String countryCode) {
		return globalService.getGlobalApplication(from, to, countryCode);
	}

	public JsonNode getIPSummary(String from, String to, String ip) {
		return globalService.getIPAnalysis(from, to, ip);
	}

	public List<JsonNode> getIPandGeoLoc(String from, String to, String countryCode, String attackCategory) {
		return globalService.getIPsandGeoLocation(countryCode, to, from, attackCategory);
	}

}
