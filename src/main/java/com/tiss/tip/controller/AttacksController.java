package com.tiss.tip.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.service.IncidentService;
import com.tiss.tip.service.MalwareIncidentService;
import com.tiss.tip.service.NetworkIncidentService;
import com.tiss.tip.service.SipIncidentService;
import com.tiss.tip.service.SshIncidentService;
import com.tiss.tip.service.WebIncidentService;

@Controller
@RequestMapping("/attacks")
public class AttacksController {

	@Autowired
	private SipIncidentService sipIncidentService;

	@Autowired
	private SshIncidentService sshIncidentService;

	@Autowired
	private MalwareIncidentService malIncidentService;

	@Autowired
	private WebIncidentService webIncidentService;

	@Autowired
	private NetworkIncidentService netIncidentService;

	@Autowired
	private IncidentService incidentService;

	static final Logger logger = LoggerFactory.getLogger(AttacksController.class);

	/// SIP Attack Info

	@RequestMapping(value = "/sip/tools", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopSipTools(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopSipTools");
		return sipIncidentService.getTopTools(from, to, size);
	}

	@RequestMapping(value = "/sip/methods", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopSipMethods(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopSipMethods");
		return sipIncidentService.getTopMethods(from, to, size);
	}

	@RequestMapping(value = "/sip/registrar-flooding-ips", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopSipRegistrar(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopSipRegistrar");
		return sipIncidentService.getRegistrarFloodingAttacks(from, to, size);
	}

	@RequestMapping(value = "/sip/options-flooding-ips", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopSipOptions(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopSipOptions");
		return sipIncidentService.getOptionsFloodingAttacks(from, to, size);
	}

	@RequestMapping(value = "/sip/proxy-flooding-ips", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopSipProxy(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopSipProxy");
		return sipIncidentService.getProxyFloodingAttacks(from, to, size);
	}

	@RequestMapping(value = "/sip/ack-flooding-ips", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopSipAck(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopSipAck");
		return sipIncidentService.getAckFloodingAttacks(from, to, size);
	}

	/// Malware Attack Info

	@RequestMapping(value = "/malware/hashes", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getMalwareHashes(@RequestParam String mal,
			@RequestParam(required = false) String from, @RequestParam(required = false) String to,
			@RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getMalwareHashes");
		return malIncidentService.getMalwareHashes(mal, from, to, size);
	}

	@RequestMapping(value = "/malware/name", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopMalwares(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopMalwares");
		return malIncidentService.getTopMalwares(from, to, size);
	}

	/// SSH Attack Info

	@RequestMapping(value = "/ssh/usernames", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopSshUsernames(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopSshUsernames");
		return sshIncidentService.getTopUsernames(from, to, size);
	}

	@RequestMapping(value = "/ssh/passwords", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopSshPasswords(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopSshPasswords");
		return sshIncidentService.getTopPasswords(from, to, size);
	}

	@RequestMapping(value = "/ssh/tools", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopSshTools(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopSshTools");
		return sshIncidentService.getTopTools(from, to, size);
	}

	@RequestMapping(value = "/web/categories", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopWebAttacks(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to,
			@RequestParam(required = false, name = "cc") String countryCode) {
		logger.info("Start getTopWebAttacks");
		return webIncidentService.getAttacks(from, to, countryCode);
	}

	//Defaults to all
	@RequestMapping(value = "{type}/ips", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getIPCountry(@PathVariable("type") String type,
			@RequestParam(required = false) String from, @RequestParam(required = false) String to,
			@RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getIPCountry from Incidents, for type [{}]", type);
		if (type.equals("probing")) {
			return netIncidentService.getTopProbingIPs(from, to, size);
		} else {
			return incidentService.getIPSrcCountry(type, from, to, size);
		}
	}
	
	@RequestMapping(value = "/{type}/unique-ips-per-country", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getCountryIPs(@PathVariable("type") String type,
			@RequestParam(required = false) String from, @RequestParam(required = false) String to,
			@RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getCountryIPs from Incidents, for type [{}]", type);
		if (type.equals("probing")) {
			return netIncidentService.getTopProbingCountriesUniqueIPs(from, to, size);
		} else {
			return incidentService.getCountryIPs(type, from, to, size);
		}
	}
	
	@RequestMapping(value = "/{type}/countries", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopCountries(@PathVariable("type") String type,
			@RequestParam(required = false) String from, @RequestParam(required = false) String to,
			@RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopCountries from Incidents, for type [{}]", type);
		if (type.equals("probing")) {
			return netIncidentService.getTopProbingCountries(from, to, size);
		} else {
			return incidentService.getTopCountry(type == null ? "all" : type, from, to, size);
		}
	}
	
	@RequestMapping(value = "/targeted-services", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getTopServices(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getTopServices");
		return incidentService.getTopServices(from, to, size);
	}
	
}
