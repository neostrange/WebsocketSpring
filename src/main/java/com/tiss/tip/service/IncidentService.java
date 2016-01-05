package com.tiss.tip.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.dal.ESQueryCreator;

@Service
public class IncidentService {
	
	@Autowired
	private ESQueryCreator queryCreator;
	
	
	public List<JsonNode> getIPSrcCountry(String type, String from, String to, int size, int minCount){
		return queryCreator.getTopIPCountries(type, from, to, size, minCount);
	}
		
	public List<JsonNode> getCountryIPs(String type, String from, String to, int size){
		return queryCreator.getTopCountryUniqueIPs(type, from, to, size);
	}
	
	public List<JsonNode> getTopCountry(String type, String from, String to, int size){
		return queryCreator.getTopCountries(type, from, to, size);
	}
		
	public List<JsonNode> getTopServices(String from, String to, int size){
		return queryCreator.getTopServicesAttacked(from, to, size);
	}
	


}
