package com.tiss.tip.dal;

import java.util.List;

import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;

import com.tiss.tip.model.Incident;
import com.tiss.tip.model.MalwareIncident;

public interface IncidentRepository extends ElasticsearchRepository<Incident, String>{

	
	public List<Incident> findByDstIP(String dstIP);
}
