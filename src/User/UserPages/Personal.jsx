import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import personalStyle from './Personal.module.css';
import axios from 'axios';
import { Col, Form } from 'react-bootstrap';
import { FaUserEdit, FaUserPlus } from "react-icons/fa";

const Personal = () => {
    const [users, setUsers] = useState([{}]);
    const username = localStorage.getItem('username');


    useEffect(() => {
        axios.get(`http://localhost:5000/personal?username=${username}`)
            .then(response => {
                setUsers(response.data);
            })
            .catch(error => {
                console.error(error);
            });
    }, []);


    return (
        <>
            <div className='container d-flex justify-content-center flex-column'>

                <div className='p-4 pt-2 pb-2 h4 d-flex align-items-center justify-content-between' style={{ color: 'var(--dark)', boxShadow: '1px 1px 10px var(--hover)', background: 'var(--lighter)', borderRadius: '10px' }}>
                    <span>Register Your Personal Information.</span>
                    <NavLink className={`mt-4 btn ${personalStyle.btn}`} to={'/personal-create'}>
                        <FaUserPlus />
                    </NavLink>
                </div>

                <br />

                <div>
                    {
                        users.map((user) => {
                            return <div>

                                <Form className={`p-4 ${personalStyle.frm}`} style={{ boxShadow: '1px 1px 10px var(--hover)', background: 'var(--lighter)', borderRadius: '10px' }}>
                                    <p className='text-danger'>** All fields are compulsory.</p>
                                    <div className="mb-3">
                                        <Form.Group as={Col} controlId="formGridEmail">
                                            <Form.Label className={personalStyle.label}>Full Name<span className='text-danger'>*</span></Form.Label>
                                            <Form.Control type='text' name='fName' value={user.fName} className={personalStyle.type} placeholder="Enter your full name" required/>
                                        </Form.Group>
                                    </div>

                                    <div className='row' >
                                        <div className='col-sm-6'>
                                            <Form.Group className="mb-3 flex-fill " controlId="formGridAddress1">
                                                <Form.Label className={personalStyle.label}>Birth Date<span className='text-danger'>*</span></Form.Label>
                                                <Form.Control type="date" name='bDate' value={user.bDate} className={personalStyle.type} placeholder="Your date of birth" required />
                                            </Form.Group>
                                        </div>

                                        <div className='col-sm-6'>
                                            <Form.Group className=" flex-fill" controlId="formGridAddress1">
                                                <Form.Label className={personalStyle.label}>Mobile No.<span className='text-danger'>*</span></Form.Label>
                                                <Form.Control type='number' name='mono' value={user.mono} className={personalStyle.type} placeholder="Your mobile number" required />
                                            </Form.Group>
                                        </div>

                                    </div>

                                    <div className='row'>
                                        <Form.Group className="mb-3" controlId="formGridAddress1">
                                            <Form.Label className={personalStyle.label}>Address<span className='text-danger'>*</span></Form.Label>
                                            <Form.Control type='text' name='address' value={user.address} className={personalStyle.type} placeholder="1234 Main St" required />
                                        </Form.Group>
                                    </div>

                                    <div className='row'>

                                        <div className='col-sm-6'>
                                            <Form.Group className="mb-3 flex-fill " controlId="formGridAddress1">
                                                <Form.Label className={personalStyle.label}>City<span className='text-danger'>*</span></Form.Label>
                                                <Form.Control type='text' name='city' value={user.city} className={personalStyle.type} placeholder="Your city" required />
                                            </Form.Group>
                                        </div>

                                        <div className='col-sm-6'>
                                            <Form.Group className="mb-3 flex-fill " controlId="formGridAddress1">
                                                <Form.Label className={personalStyle.label}>State<span className='text-danger'>*</span></Form.Label>
                                                <Form.Control type='text' name='state' value={user.state} className={personalStyle.type} placeholder="Your state" required />
                                            </Form.Group>
                                        </div>

                                    </div>



                                    <div className='h4 d-flex align-items-center justify-content-between' style={{ color: 'var(--dark)', background: 'var(--lighter)', borderRadius: '10px' }}>
                                        <span>Already Registered?</span>
                                        <NavLink className={`mt-4 btn ${personalStyle.btn}`} to={`/personal-edit/${user._id}`}>
                                            <FaUserEdit />
                                        </NavLink>
                                    </div>
                                </Form>
                            </div>
                        })
                    }
                </div>

            </div>
        </>
    )
}

export default Personal