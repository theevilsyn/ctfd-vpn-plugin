from CTFd import utils
from CTFd.models import db, Solves, Fails, Flags, Challenges, ChallengeFiles, Tags, Hints
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES
from CTFd.plugins.flags import get_flag_class
from CTFd.utils.config import is_teams_mode
from CTFd.utils.config.visibility import challenges_visible
from CTFd.utils.uploads import delete_file
from CTFd.utils.user import get_ip, is_admin, authed, get_current_user, get_current_team
from flask import session, abort, send_file
from io import BytesIO
import json
import logging
import os

from .config import registrar_host, registrar_port

try:
    from urllib.parse import quote
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:
    from urllib import quote
    from urllib2 import urlopen, HTTPError

plugin_dirname = os.path.basename(os.path.dirname(__file__))
logger = logging.getLogger('pentest')
registrar_timeout = 10

class PentestChallengeModel(Challenges):
    __mapper_args__ = {'polymorphic_identity': 'pentest'}
    id = db.Column(None, db.ForeignKey('challenges.id'), primary_key=True)
    pentestchall_name = db.Column(db.String(80))

    def __init__(self, name, description, value, category, state, pentestchall_name, type='pentest'):
        self.name = name
        self.description = description
        self.value = value
        self.category = category
        self.type = type
        self.state = state
        self.pentestchall_name = pentestchall_name

class pentestChallenge(BaseChallenge):
    id = "pentest"  # Unique identifier used to register challenges
    name = "pentest"  # Name of a challenge type
    templates = {  # Nunjucks templates used for each aspect of challenge editing & viewing
        'create': '/plugins/{0}/assets/create.html'.format(plugin_dirname),
        'update': '/plugins/{0}/assets/update.html'.format(plugin_dirname),
        'view': '/plugins/{0}/assets/view.html'.format(plugin_dirname),
    }
    scripts = {  # Scripts that are loaded when a template is loaded
        'create': '/plugins/{0}/assets/create.js'.format(plugin_dirname),
        'update': '/plugins/{0}/assets/update.js'.format(plugin_dirname),
        'view': '/plugins/{0}/assets/view.js'.format(plugin_dirname),
    }

    @staticmethod
    def create(request):
        """
        This method is used to process the challenge creation request.

        :param request:
        :return:
        """
        data = request.form or request.get_json()

        challenge = pentestChallengeModel(**data)

        db.session.add(challenge)
        db.session.commit()

        return challenge

    @staticmethod
    def read(challenge):
        """
        This method is in used to access the data of a challenge in a format processable by the front end.

        :param challenge:
        :return: Challenge object, data dictionary to be returned to the user
        """
        data = {
            'id': challenge.id,
            'name': challenge.name,
            'value': challenge.value,
            'description': challenge.description,
            'category': challenge.category,
            'pentestchall_name': challenge.pentestchall_name,
            'state': challenge.state,
            'max_attempts': challenge.max_attempts,
            'type': challenge.type,
            'type_data': {
                'id': pentestChallenge.id,
                'name': pentestChallenge.name,
                'templates': pentestChallenge.templates,
                'scripts': pentestChallenge.scripts,
            }
        }
        return data

    @staticmethod
    def update(challenge, request):
        """
        This method is used to update the information associated with a challenge. This should be kept strictly to the
        Challenges table and any child tables.

        :param challenge:
        :param request:
        :return:
        """
        data = request.form or request.get_json()
        for attr, value in data.items():
            setattr(challenge, attr, value)

        db.session.commit()
        return challenge

    @staticmethod
    def delete(challenge):
        """
        This method is used to delete the resources used by a challenge.

        :param challenge:
        :return:
        """
        Fails.query.filter_by(challenge_id=challenge.id).delete()
        Solves.query.filter_by(challenge_id=challenge.id).delete()
        Flags.query.filter_by(challenge_id=challenge.id).delete()
        files = ChallengeFiles.query.filter_by(challenge_id=challenge.id).all()
        for f in files:
            delete_file(f.id)
        ChallengeFiles.query.filter_by(challenge_id=challenge.id).delete()
        Tags.query.filter_by(challenge_id=challenge.id).delete()
        Hints.query.filter_by(challenge_id=challenge.id).delete()
        pentestChallengeModel.query.filter_by(id=challenge.id).delete()
        Challenges.query.filter_by(id=challenge.id).delete()
        db.session.commit()

    @staticmethod
    def attempt(challenge, request):
        """
        This method is used to check whether a given input is right or wrong. It does not make any changes and should
        return a boolean for correctness and a string to be shown to the user. It is also in charge of parsing the
        user's input from the request itself.

        :param challenge: The Challenge object from the database
        :param request: The request the user submitted
        :return: (boolean, string)
        """
        data = request.form or request.get_json()
        submission = data['submission'].strip()
        flags = Flags.query.filter_by(challenge_id=challenge.id).all()
        for flag in flags:
            if get_flag_class(flag.type).compare(flag, submission):
                return True, 'Correct'
        return False, 'Incorrect'

    @staticmethod
    def solve(user, team, challenge, request):
        """
        This method is used to insert Solves into the database in order to mark a challenge as solved.

        :param team: The Team object from the database
        :param chal: The Challenge object from the database
        :param request: The request the user submitted
        :return:
        """
        data = request.form or request.get_json()
        submission = data['submission'].strip()
        solve = Solves(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(req=request),
            provided=submission
        )
        db.session.add(solve)
        db.session.commit()
        db.session.close()

    @staticmethod
    def fail(user, team, challenge, request):
        """
        This method is used to insert Fails into the database in order to mark an answer incorrect.

        :param team: The Team object from the database
        :param chal: The Challenge object from the database
        :param request: The request the user submitted
        :return:
        """
        data = request.form or request.get_json()
        submission = data['submission'].strip()
        wrong = Fails(
            user_id=user.id,
            team_id=team.id if team else None,
            challenge_id=challenge.id,
            ip=get_ip(request),
            provided=submission
        )
        db.session.add(wrong)
        db.session.commit()
        db.session.close()

def user_can_get_config():
    if is_admin():
        return True
    if not authed():
        return False
    if not challenges_visible():
        return False
    return True

def send_config(host, escaped_chalname, escaped_clientname):
    url = "http://{0}/{1}/get?cn={2}".format(host, escaped_chalname, escaped_clientname)
    logger.debug("Requesting: {0}".format(url))
    resp = urlopen(url, timeout=registrar_timeout)
    config = json.loads(resp.read().decode('utf-8')).encode('utf-8')
    return send_file(
        BytesIO(config),
        attachment_filename="{0}.ovpn".format(escaped_chalname),
        as_attachment=True
    )

def load(app):
    app.db.create_all()
    CHALLENGE_CLASSES['pentest'] = pentestChallenge

    # Intitialize logging.
    logger.setLevel(logging.INFO)

    log_dir = app.config.get('LOG_FOLDER', os.path.join(os.path.dirname(__file__), 'logs'))
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, 'pentest.log')

    if not os.path.exists(log_file):
        open(log_file, 'a').close()

    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=10000)
    logger.addHandler(handler)
    logger.propagate = 0

    @app.route('/pentest/config/<int:chalid>', methods=['GET'])
    def registrar(chalid):
        if not user_can_get_config():
            logger.info("[403] Client {0} requested config for challenge {1}: Not authorized".format(session.get('clientname', '<not authed>'), chalid))
            abort(403)

        if is_teams_mode():
            clientname = get_current_team().name
        else:
            clientname = get_current_user().name

        chal = pentestChallengeModel.query.filter_by(id=chalid).first_or_404()
        if chal.state == 'hidden':
            logger.info("[404] Client {0} requested config for hidden challenge {1}".format(clientname, chal.name))
            abort(404)

        escaped_clientname = quote(clientname)
        escaped_chalname = quote(chal.pentestchall_name, safe='')
        host = "{0}:{1}".format(registrar_host, registrar_port)

        try:
            resp = send_config(host, escaped_chalname, escaped_clientname)
            logger.info("[200] Client {0} requested config for challenge {1}".format(clientname, chal.name))
            return resp
        except HTTPError as err:
            if err.code != 404:
                logger.info("[500] Config retrival failed for challenge {0}".format(chal.name))
                raise

        try:
            # The certs had not been generated yet. Generate them now
            url = "http://{0}/{1}/add?cn={2}".format(host, escaped_chalname, escaped_clientname)
            logger.debug("Requesting: {0}".format(url))
            urlopen(url, timeout=registrar_timeout)

            resp = send_config(host, escaped_chalname, escaped_clientname)
            logger.info("[200] Client {0} requested new config for challenge {1}".format(clientname, chal.name))
            return resp
        except HTTPError:
            logger.info("[500] Config creation failed for challenge {0}".format(chal.name))
            raise

    register_plugin_assets_directory(app, base_path='/plugins/{0}/assets/'.format(plugin_dirname))
