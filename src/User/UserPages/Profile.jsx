import React from 'react';
import profileStyle from './Profile.module.css';
import Personal from './Personal';
import user from './user.jpg';

const Profile = () => {

    return (
        <>

            <div className='container-fluid'>
                <div className='row'>
                    <div className='col-md-6 d-flex align-items-center' >
                        <div>
                            <img alt='user' src={user} className={`img-fluid ${profileStyle.img}`} />
                        </div>

                    </div>
                    <div className='col-md-6'>
                        <Personal />
                    </div>
                </div>

            </div>
        </>
    );
};

export default Profile;