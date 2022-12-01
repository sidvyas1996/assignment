package com.emeritus.assignment.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin")
/*
*       -Create/Update/Delete/List Users (Instructor, Student)
		- List all courses
		- List all Students
		- List students enrolled in each course
* */
public class AdminController {

    @PostMapping("/user")
    public ResponseEntity<?> createUser(){
         return ResponseEntity.ok("User created successfully!");
    }

    @PutMapping("/user")
    public ResponseEntity<?> updateUser(){
        return ResponseEntity.ok("User updated successfully!");
    }

    @DeleteMapping("/user")
    public ResponseEntity<?> deleteUser(){
        return ResponseEntity.ok("user deleted successfully!");
    }
    @GetMapping("/user")
    public ResponseEntity<?> getUser(){
        return ResponseEntity.ok("User A");
    }

    @GetMapping("/courses")
    public ResponseEntity<?> viewAllCourses()
    {
        //find all list of courses
        return ResponseEntity.ok(List.of("French","Java","Python"));
    }

    @GetMapping("/students")
    public ResponseEntity<?> viewAllStudents()
    {
        //find all list of courses
        return ResponseEntity.ok(List.of("Student A","Student B","Student C"));
    }
}
