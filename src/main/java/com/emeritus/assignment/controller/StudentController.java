package com.emeritus.assignment.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/student")
/*- Student
		- Can see all the courses
		- Can enroll in more than one course
		- Can access only enrolled courses and assignments
		- Can submit/update assignments
		*/
public class StudentController {

    @GetMapping("/courses")
    public ResponseEntity<?> viewAllCourses()
    {
        //find all list of courses
        return ResponseEntity.ok(List.of("French","Java","Python"));
    }

    @PostMapping("/enroll")
    public ResponseEntity<?> enrollInCourse()
    {
        //find all list of courses
        return ResponseEntity.ok("Student enrolled successfully!");
    }

    @GetMapping("/enrolledCourses")
    public ResponseEntity<?> viewMyEnrolledCourses()
    {
        //find all list of courses
        return ResponseEntity.ok(List.of("Java","Spring"));
    }

    @PostMapping("/assignment")
    public ResponseEntity<?> submitAssignment()
    {
        //find all list of courses
        return ResponseEntity.ok("Assignment submitted successfully");
    }

}
