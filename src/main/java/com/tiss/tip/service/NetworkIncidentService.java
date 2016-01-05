package com.tiss.tip.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.dal.ESQueryCreator;

@Service
public class NetworkIncidentService {

	@Autowired
	private ESQueryCreator queryService;

	public List<JsonNode> getTopProbingIPs(String from, String to, int size, int minCount) {
		return queryService.getTopProbingIPs(from, to, size, minCount);
	}

	public List<JsonNode> getTopProbingCountriesUniqueIPs(String from, String to, int size) {
		return queryService.getTopProbingCountriesUniqueIPs(from, to, size);
	}
	
	public List<JsonNode> getTopProbingCountries(String from, String to, int size) {
		return queryService.getTopProbingCountries(from, to, size);
	}
}
