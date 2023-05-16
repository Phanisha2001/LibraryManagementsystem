package com.LibraryManagementSystem.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.LibraryManagementSystem.entity.Publisher;

public interface PublisherRepository extends JpaRepository<Publisher, Long> {

}
