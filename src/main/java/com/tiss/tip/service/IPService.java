package com.tiss.tip.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.dal.IPQueryCreator;
import com.tiss.tip.model.Incident;

@Service
public class IPService {

	@Autowired
	IPQueryCreator queryCreator;

	public JsonNode getIPSummary(String ip) {
		return queryCreator.getIPAnalysis(ip);
	}

	public List<JsonNode> getIPHistory(String from, String to, String ip, int size) {
		return queryCreator.getIPHistory(from, to, ip, size);
	}

	public List<JsonNode> getIPActivityTimeline(String from, String to, String ip) {
		return queryCreator.getIPActivityTimeline(from, to, ip);
	}
	
	public List<JsonNode> getIPActivitySummary(String from, String to, String ip) {
		return queryCreator.getIPActivitySummary(from, to, ip);
	}
	
	public JsonNode getIPProbingAttempts(String from, String to, String ip) {
		return queryCreator.getIPProbingAttempts(from, to, ip);
	}
	
	public JsonNode getIPGeoInfo(String ip) {
		return queryCreator.getIPGeoInfo(ip);
	}
}
