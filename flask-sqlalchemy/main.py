from flask import Flask, render_template, request, make_response, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash
from werkzeug.utils import redirect
from wtforms import PasswordField, TextAreaField, SubmitField, StringField, BooleanField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired
from data import db_session
from data.users import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


class RegisterForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    password_again = PasswordField('Повторите пароль', validators=[DataRequired()])
    surname = StringField('Фамилия пользователя', validators=[DataRequired()])
    name = StringField('Имя пользователя', validators=[DataRequired()])
    age = StringField('Возраст', validators=[DataRequired()])
    speciality = StringField('Профессия', validators=[DataRequired()])
    address = StringField('Адрес', validators=[DataRequired()])
    # about = TextAreaField("Немного о себе")
    submit = SubmitField('Войти')


class JobsForm(FlaskForm):
    team_leader = StringField('team leader id')
    job = StringField('job title')
    work_size = StringField('work size(hours)')
    collaborators = StringField("list of collaborators's ids")
    is_finished = BooleanField('Is job finished?')
    submit = SubmitField('Применить')

class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


def main():
    db_session.global_init("db/mars_explorer.db")
    session = db_session.create_session()

    @app.route('/jobs', methods=['GET', 'POST'])
    def add_news():
        form = JobsForm()
        if form.validate_on_submit():
            session = db_session.create_session()
            job = Jobs()
            job.job = form.job.data
            job.team_leader = int(form.team_leader.data)
            job.work_size = int(form.work_size.data)
            job.collaborators = form.collaborators.data
            job.is_finished = form.is_finished.data
            session.add(job)
            session.commit()
            return redirect('/')
        return render_template('jobs.html', title='Добавление новости',
                               form=form)

    @app.route("/")
    def index():
        session = db_session.create_session()
        jobs = []
        if current_user.is_authenticated:
            for job in session.query(Jobs).all():
                if current_user.id in list(map(int, job.collaborators.split(', '))):
                    jobs.append(job)
        else:
            jobs = session.query(Jobs).all()
        return render_template("index.html", news=jobs)

    @app.route('/register', methods=['GET', 'POST'])
    def reqister():
        form = RegisterForm()
        if form.validate_on_submit():
            if form.password.data != form.password_again.data:
                return render_template('register.html', title='Регистрация',
                                       form=form,
                                       message="Пароли не совпадают")
            session = db_session.create_session()
            if session.query(User).filter(User.email == form.email.data).first():
                return render_template('register.html', title='Регистрация',
                                       form=form,
                                       message="Такой пользователь уже есть")
            user = User()
            user.surname = form.surname.data
            user.name = form.name.data
            user.age = form.age.data
            user.speciality = form.speciality.data
            user.address = form.address.data
            user.email = form.email.data
            user.hashed_password = form.password.data
            # user = users.User(
            #    name=form.name.data,
            #    email=form.email.data)
            #  #  surname=form.surname.data,
            #  age=int(form.age.data),
            # position=form.position.data,
            #  address=form.address.data)
            user.set_password(form.password.data)
            session.add(user)
            session.commit()
            return redirect('/login')
        return render_template('register.html', title='Регистрация', form=form)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        form = LoginForm()
        if form.validate_on_submit():
            session = db_session.create_session()
            user = session.query(User).filter(User.email == form.email.data).first()
            if user and user.check_password(form.password.data):
                login_user(user, remember=form.remember_me.data)
                return redirect("/")
            return render_template('login.html',
                                   message="Неправильный логин или пароль",
                                   form=form)
        return render_template('login.html', title='Авторизация', form=form)

    # @app.route("/cookie_test")
    # def cookie_test():
    #    visits_count = int(request.cookies.get("visits_count", 0))
    #    if visits_count:
    #        res = make_response(f"Вы пришли на эту страницу {visits_count + 1} раз")
    #        res.set_cookie("visits_count", str(visits_count + 1),
    #                       max_age=60 * 60 * 24 * 365 * 2)
    #    else:
    #        res = make_response(
    #            "Вы пришли на эту страницу в первый раз за последние 2 года")
    #        res.set_cookie("visits_count", '1',
    #                       max_age=60 * 60 * 24 * 365 * 2)
    #    return res


    # @app.route('/session_test/')
    # def session_test():
    #    if 'visits_count' in session:
    #        session['visits_count'] = session.get('visits_count') + 1
    #    else:
    #        session['visits_count'] = 1
    #    return str(session.get('visits_count'))

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect("/login")

    # @app.route('/news/<int:id>', methods=['GET', 'POST'])
    # @login_required
    # def edit_news(id):
    #     form = NewsForm()
    #     if request.method == "GET":
    #         session = db_session.create_session()
    #         news = session.query(News).filter(News.id == id,
    #                                           News.user == current_user).first()
    #         if news:
    #             form.title.data = news.title
    #             form.content.data = news.content
    #             form.is_private.data = news.is_private
    #         else:
    #             abort(404)
    #     if form.validate_on_submit():
    #        session = db_session.create_session()
    #         news = session.query(News).filter(News.id == id,
    #                                          News.user == current_user).first()
    #         if news:
    #             news.title = form.title.data
    #             news.content = form.content.data
    #             news.is_private = form.is_private.data
    #             session.commit()
    #             return redirect('/')
    #         else:
    #             abort(404)
    #     return render_template('news.html', title='Редактирование новости', form=form)

    # @app.route('/news_delete/<int:id>', methods=['GET', 'POST'])
    # @login_required
    # def news_delete(id):
    #    session = db_session.create_session()
    #    news = session.query(News).filter(News.id == id,
    #                                     News.user == current_user).first()
    #   if news:
    #        session.delete(news)
    #        session.commit()
    #    else:
    #        abort(404)
    #    return redirect('/')

    app.run()


if __name__ == '__main__':
    main()
