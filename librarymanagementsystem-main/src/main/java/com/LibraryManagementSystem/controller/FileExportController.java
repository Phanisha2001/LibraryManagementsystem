package com.LibraryManagementSystem.controller;

import javax.servlet.http.HttpServletResponse;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.LibraryManagementSystem.service.FileService;

@Controller
public class FileExportController {

	final FileService fileService;

	public FileExportController(FileService fileService) {
		this.fileService = fileService;
	}

	@GetMapping("/export/{fileName}")
	public void exportCSV(@PathVariable(value = "fileName") String fileName, HttpServletResponse response)
			throws Exception {
		fileService.exportCSV(fileName, response);
	}

}
