package com.tiss.tip.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.dal.ESQueryCreator;

@Service
public class SshIncidentService {
	
	@Autowired
	private ESQueryCreator queryService;

	public List<JsonNode> getTopUsernames(String from, String to, int size) {
		return queryService.getTopSshUsernames(from, to, size, null);
	}
	
	public List<JsonNode> getTopPasswords(String from, String to, int size) {
		return queryService.getTopSshPasswords(from, to, size, null);
	}
	
	public List<JsonNode> getTopUsernamePasswords(String from, String to, int size) {
		return queryService.getTopSshUsernamePasswordPairs(from, to, size);
	}
	
	public List<JsonNode> getTopTools(String from, String to, int size) {
		return queryService.getTopSshTools(from, to, size, null);
	}
	
	public List<JsonNode> getTopInputs(String from, String to, int size) {
		return queryService.getTopSshInputs(from, to, size, null);
	}

	
}
