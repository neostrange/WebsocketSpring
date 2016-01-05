package com.tiss.tip.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.dal.ESQueryCreator;

@Service
public class SipIncidentService {

	@Autowired
	private ESQueryCreator queryService;

	public List<JsonNode> getTopTools(String from, String to, int size) {
		return queryService.getTopSipTools(from, to, size, null);
	}

	public List<JsonNode> getTopMethods(String from, String to, int size) {
		return queryService.getTopSipMethods(from, to, size, null);
	}

	public List<JsonNode> getRegistrarFloodingAttacks(String from, String to, int size) {
		return queryService.getSipRegistrarFloodingAttacks(from, to, size, null);
	}

	public List<JsonNode> getOptionsFloodingAttacks(String from, String to, int size) {
		return queryService.getSipOptionsFloodingAttacks(from, to, size, null);
	}

	public List<JsonNode> getProxyFloodingAttacks(String from, String to, int size) {
		return queryService.getSipProxyFloodingAttacks(from, to, size, null);
	}

	public List<JsonNode> getAckFloodingAttacks(String from, String to, int size) {
		return queryService.getSipAckFloodingAttacks(from, to, size, null);
	}

}
