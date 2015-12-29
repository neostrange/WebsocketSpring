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
	
	public JsonNode getIPSummary(String from, String to, String ip) {
		return queryCreator.getIPAnalysis(from, to, ip);
	}
	
	public List<Incident> getIPHistory(String from, String to, String ip, int size) {
		return queryCreator.getIPHistory(from, to, ip, size);
	}
}
