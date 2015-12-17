package com.tiss.tip.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tiss.tip.dal.IncidentRepository;
import com.tiss.tip.model.Incident;



@Service
public class IncidentService {
	
	@Autowired
	private IncidentRepository repository;
	
	public List<Incident> getByDstIP(String dstIP){
		return repository.findByDstIP(dstIP);
	}
	
	
	
	

}
