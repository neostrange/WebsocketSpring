package com.tiss.tip.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.elasticsearch.core.ElasticsearchTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.model.Incident;
import com.tiss.tip.model.MalwareIncident;
import com.tiss.tip.service.MalwareIncidentService;
import com.tiss.tip.service.NRTService;

/**
 * Handles requests for the application home page.
 */

@Controller
@RequestMapping("/")
public class HomeController {

	@Autowired
	public ElasticsearchTemplate elasticsearchTemplate;

	@Autowired
	private NRTService nrtService;

	private static final Logger logger = LoggerFactory.getLogger(HomeController.class);

	/**
	 * Simply selects the home view to render by returning its name.
	 */

	@RequestMapping(value = "/", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getRTIncidents(
			@RequestParam(required = false, defaultValue = "60") int interval) {
		logger.info("Start getIncidents");
		return nrtService.getRecentIncidentActivity(interval);
	}

	@RequestMapping(value = "/counts", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getRTCounts(@RequestParam(required = false, defaultValue = "60") int interval) {
		logger.info("Start getRTCounts");
		return nrtService.getRecentActivityCounts(interval);
	}

}
