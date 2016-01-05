package com.tiss.tip.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.dal.ESQueryCreator;

@Service
public class NRTService {

	@Autowired
	private ESQueryCreator queryService;
	
	public List<JsonNode> getRecentIncidentActivity(int interval) {
		return queryService.createRTIncidentsQuery(interval);
	}
	
	public List<JsonNode> getRecentActivityCounts(int interval) {
		return queryService.getRTCounts(interval);
	}
	

}
