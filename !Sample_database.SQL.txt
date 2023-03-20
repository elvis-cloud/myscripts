-- This Transact-SQL script creates all tables that are used
-- in the book "SQL Server 2016: A Beginner's guide".
-- It loads also all data in the four existing tables.

-- NOTE, please !!
-- Create first the database (sample), using CREATE DATABASE statement 

USE sample;
CREATE TABLE employee  (emp_no INTEGER NOT NULL, 
                        emp_fname CHAR(20) NOT NULL,
                        emp_lname CHAR(20) NOT NULL,
                        dept_no CHAR(4) NULL);

CREATE TABLE department(dept_no CHAR(4) NOT NULL,
                        dept_name CHAR(25) NOT NULL,
                        location CHAR(30) NULL);

CREATE TABLE project   (project_no CHAR(4) NOT NULL,
                        project_name CHAR(15) NOT NULL,
                        budget FLOAT NULL);

CREATE TABLE works_on	(emp_no INTEGER NOT NULL,
                        project_no CHAR(4) NOT NULL,
                        job CHAR (15) NULL,
                        enter_date DATE NULL);

insert into employee values(25348, 'Matthew', 'Smith',    'd3');
insert into employee values(10102, 'Ann',     'Jones',    'd3');
insert into employee values(18316, 'John',    'Barrimore','d1');
insert into employee values(29346, 'James',   'James',    'd2');
insert into employee values(9031,  'Elke',    'Hansel',   'd2');
insert into employee values(2581,  'Elsa',    'Bertoni',  'd2');
insert into employee values(28559, 'Sybill',  'Moser',    'd1');

insert into department values ('d1', 'Research',   'Dallas');
insert into department values ('d2', 'Accounting', 'Seattle');
insert into department values ('d3', 'Marketing',  'Dallas');

insert into project values ('p1', 'Apollo', 120000.00);
insert into project values ('p2', 'Gemini', 95000.00);
insert into project values ('p3', 'Mercury', 186500.00);

insert into works_on values (10102, 'p1',  'Analyst',   '2016.10.1');
insert into works_on values (10102, 'p3',  'Manager',   '2018.1.1');
insert into works_on values (25348, 'p2',  'Clerk',     '2017.2.15');
insert into works_on values (18316, 'p2',  NULL,        '2017.6.1');
insert into works_on values (29346, 'p2',  NULL,        '2016.12.15');
insert into works_on values (2581,  'p3',  'Analyst',   '2017.10.15');
insert into works_on values (9031,  'p1',  'Manager',   '2017.4.15');
insert into works_on values (28559, 'p1',  NULL,        '2017.8.1');
insert into works_on values (28559, 'p2',  'Clerk',     '2018.2.1')
insert into works_on values (9031,  'p3',  'Clerk',     '2016.11.15');  
insert into works_on values (29346, 'p1',  'Clerk',     '2017.1.4');


