import axios from 'axios';
import React, { useState, useEffect } from 'react';
import earn from './EarnedLeaveData.module.css'


const LeaveDisplayData = () => {
    const [user, setUser] = useState([]);

    useEffect(() => {
        axios.get('http://localhost:5000/getUsers')
            .then(user =>
                setUser(user.data)
            )
            .catch(error => {
                console.error(error);
            })
    }, []);

    return (
        <>
            <div className='overflow-x-auto'>
                <table className='table table-bordered text-center table-hover table-responsive'  >
                    <thead style={{ color: 'var(--darker)' }}>
                        <th >
                            UserName
                        </th>
                        <th>
                            Email Id
                        </th>
                        <th>
                            Status
                        </th>
                    </thead>

                    <tbody id={earn.table}>
                        {user.map(user => (
                            <tr key={user._id}>
                                <td>
                                    {user.emp_name}
                                </td>
                                <td>
                                    {user.email}
                                </td>
                                <td>
                                    {user.status}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </>
    );
}

export default LeaveDisplayData;
