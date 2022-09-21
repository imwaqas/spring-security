package com.example.demo.student;


import java.util.Arrays;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {


  private static final List<Student> STUDENTS= Arrays.asList(new Student(1,"Waqas"),
      new Student(2,"syed"));

  @GetMapping
  @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_TRAINEE')")
  public List<Student> getAllSTUDENTS() {
    return STUDENTS;
  }

  @PostMapping
  @PreAuthorize("hasAuthority('student:write')")
  public void registerNewStudent(@RequestBody Student student){


  }

  @DeleteMapping(path="{studentId}")
  @PreAuthorize("hasAuthority('student:write')")
  public void deleteStudent(@PathVariable("studentId") Integer studentId){


    System.out.println("delete");
    System.out.println(studentId);


  }

  @PutMapping(path="{studentId}")
  @PreAuthorize("hasAuthority('student:write')")
  public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody  Student student){
    System.out.println(String.format("%s %s",student,student));

  }
}
