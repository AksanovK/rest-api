package ru.itis.rest_api.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import ru.itis.rest_api.dto.TeacherDto;
import ru.itis.rest_api.models.Teacher;
import ru.itis.rest_api.repositories.TeachersRepository;
import static ru.itis.rest_api.dto.TeacherDto.from;

import java.util.List;

@Service
public class TeachersServiceImpl implements TeachersService {

    @Autowired
    private TeachersRepository teachersRepository;

    @Override
    public List<TeacherDto> getAllTeachers() {
        return from(teachersRepository.findAllByIsDeletedIsNull());
    }

    @Override
    public TeacherDto addTeacher(TeacherDto teacher) {
        Teacher newTeacher = Teacher.builder()
                .firstName(teacher.getFirstName())
                .lastName(teacher.getLastName())
                .build();

        teachersRepository.save(newTeacher);
        return from(newTeacher);
    }

    @Override
    public TeacherDto updateTeacher(Long teacherId, TeacherDto teacher) {
        Teacher teacherForUpdate = teachersRepository.findById(teacherId)
                .orElseThrow(IllegalArgumentException::new);
        teacherForUpdate.setFirstName(teacher.getFirstName());
        teacherForUpdate.setLastName(teacher.getLastName());
        teachersRepository.save(teacherForUpdate);
        return from(teacherForUpdate);
    }

    @Override
    public void deleteTeacher(Long teacherId) {
        Teacher teacherForDelete = teachersRepository.findById(teacherId)
                .orElseThrow(IllegalArgumentException::new);
        teacherForDelete.setIsDeleted(true);
        teachersRepository.save(teacherForDelete);
    }

}
