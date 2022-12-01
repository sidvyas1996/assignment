package com.emeritus.assignment.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/instructor")
/*
* - Instructor
		- Create Courses
		- Create Assignment for each course
		- List all courses
		- Access/Modify courses created by themselves
		- List the students enrolled in each course
		- Must not be able to access courses created by other instuctors
* */
public class InstructorController {

    @PostMapping("/courses")
    public ResponseEntity<?> createCourses(){
        return ResponseEntity.ok("course created successfully!");
    }

    @PostMapping("/assignments")
    public ResponseEntity<?> createAssignments(){
        return ResponseEntity.ok("assignment created successfully!");
    }

    @GetMapping("/courses")
    public ResponseEntity<?> viewAllCourses()
    {
        //find all list of courses
        return ResponseEntity.ok(List.of("French","Java","Python"));
    }

    @PutMapping("/courses")
    public ResponseEntity<?> modifyCourses(){
        return ResponseEntity.ok("course created successfully!");
    }

    @GetMapping("/students")
    public ResponseEntity<?> viewAllStudentsInCourse()
    {
        //find all list of courses
        return ResponseEntity.ok(List.of("Student A","Student B","Student C"));
    }
}
