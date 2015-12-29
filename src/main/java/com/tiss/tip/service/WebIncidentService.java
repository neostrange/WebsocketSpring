package com.tiss.tip.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.dal.ESQueryCreator;

@Service
public class WebIncidentService {

	@Autowired
	private ESQueryCreator queryService;
	
	public List<JsonNode> getAttacks(String from, String to, String countryCode){
		return queryService.getTopWebAttacks(from, to, countryCode);
	}
}
