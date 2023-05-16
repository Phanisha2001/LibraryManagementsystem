package com.LibraryManagementSystem.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.LibraryManagementSystem.entity.Author;

public interface AuthorRepository extends JpaRepository<Author, Long> {

}
